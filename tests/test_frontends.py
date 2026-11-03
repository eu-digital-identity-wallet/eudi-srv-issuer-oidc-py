"""One issuer per frontend: <issuer>/<frontend id> (upstream #12, #5)."""

import json
from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import server
from conftest import FE, FRONTEND_ID, OTHER_FRONTEND_ID, PREFIX, _test_config, make_wia_headers
from security import load_frontends
from test_security import CLIENT_ID, REDIRECT_URI, VERIFIER, _authorize, _dpop_proof
from test_views import API_KEY, PREAUTH_GRANT, _code, _par, key  # noqa: F401 (fixture)

ISSUER = "https://issuer.eudiw.dev/oidc"
OTHER = f"{PREFIX}/{OTHER_FRONTEND_ID}"


def _token(client, path, data, key, frontend_id=FRONTEND_ID):
    """A token request at a frontend's issuer, authenticated for that issuer."""
    issuer = f"{ISSUER}/{frontend_id}"
    return client.post(
        f"{path}/token",
        data=data,
        headers={**make_wia_headers(issuer), "DPoP": _dpop_proof(key, htu=f"{issuer}/token")},
    )


def _code_grant(code):
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": VERIFIER,
    }


class TestIssuer:
    def test_authorization_response_iss_is_the_frontends_issuer(self, client):
        # RFC 9207: the iss of the response is the issuer in the metadata.
        mine = _authorize(client)
        location = client.get(
            PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]}
        ).headers["Location"]
        assert parse_qs(urlsplit(location).query)["iss"] == [f"{ISSUER}/{FRONTEND_ID}"]
        metadata = client.get(FE + "/.well-known/oauth-authorization-server").get_json()
        assert metadata["issuer"] == f"{ISSUER}/{FRONTEND_ID}"

    def test_access_token_iss_and_introspection(self, client, key):
        tokens = _token(client, FE, _code_grant(_code(client)), key).get_json()
        assert pyjwt.decode(tokens["access_token"], options={"verify_signature": False})["iss"] == f"{ISSUER}/{FRONTEND_ID}"
        # The server still verifies the tokens it issued as the frontend's issuer.
        introspected = client.post(PREFIX + "/introspection", data={"token": tokens["access_token"]}, headers=API_KEY)
        assert introspected.get_json()["active"] is True

    @pytest.mark.parametrize("aud", [ISSUER, f"{ISSUER}/{OTHER_FRONTEND_ID}"])
    def test_attestation_pop_names_the_frontends_issuer(self, client, aud):
        response = client.post(
            FE + "/pushed_authorization",
            data={"client_id": "wallet-test", "redirect_uri": REDIRECT_URI, "response_type": "code", "scope": "x"},
            headers=make_wia_headers(aud),
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_client"


class TestBinding:
    """A grant is used at the issuer of the frontend it was issued for."""

    def test_request_uri_of_another_frontend(self, client, wia):
        request_uri = _par(client, wia()).get_json()["request_uri"]
        response = client.get(OTHER + "/authorization", query_string={"client_id": CLIENT_ID, "request_uri": request_uri})
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request_uri"

    def test_codes_and_refresh_tokens_of_another_frontend(self, client, key):
        code = _code(client)
        response = _token(client, OTHER, _code_grant(code), key, OTHER_FRONTEND_ID)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"
        # The refused attempt did not use up the code.
        tokens = _token(client, FE, _code_grant(code), key).get_json()
        refresh = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": CLIENT_ID}
        response = _token(client, OTHER, refresh, key, OTHER_FRONTEND_ID)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"
        assert _token(client, FE, refresh, key).status_code == 200

    def test_pre_authorized_code_of_another_frontend(self, client, key):
        offer = client.post(
            PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers=API_KEY
        ).get_json()
        grant = {"grant_type": PREAUTH_GRANT, "pre-authorized_code": offer["preauth_code"], "tx_code": str(offer["tx_code"])}
        response = _token(client, OTHER, grant, key, OTHER_FRONTEND_ID)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"
        assert _token(client, FE, grant, key).status_code == 200

    def test_dpop_proof_for_another_frontend(self, client, wia, key):
        # RFC 9449 section 4.3: the htu is this request's URI, not another issuer's.
        other = f"{ISSUER}/{OTHER_FRONTEND_ID}"
        response = _par(client, {**wia(), "DPoP": _dpop_proof(key, htu=f"{other}/pushed_authorization")})
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"
        grant = _code_grant(_code(client))
        response = client.post(FE + "/token", data=grant, headers={**wia(), "DPoP": _dpop_proof(key, htu=f"{other}/token")})
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"
        assert _token(client, FE, grant, key).status_code == 200

    @pytest.mark.parametrize("data", [{}, {"frontend_id": "unknown"}])
    def test_preauth_generate_needs_a_known_frontend(self, client, data):
        response = client.post(PREFIX + "/preauth_generate", data={"scope": "x", **data}, headers=API_KEY)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"


class TestConfiguration:
    @pytest.mark.parametrize(
        "frontends", [None, [], ["a/b"], ["a.b"], [""], ["static"], ["introspection"], [42]]
    )
    def test_invalid_frontends(self, frontends):
        with pytest.raises(ValueError):
            load_frontends(frontends)

    def test_frontends_in_order_without_duplicates(self):
        assert load_frontends(["b", "a", "b", "fe_1-x"]) == ("b", "a", "fe_1-x")

    def test_issuer_without_a_path(self, tmp_path):
        # Own hostname, no reverse proxy: issuers are https://as.test/<frontend id>.
        path = _test_config(tmp_path)
        with open(path) as f:
            config = json.load(f)
        config["domain"] = "as.test"
        config["frontends"] = [FRONTEND_ID]
        with open(path, "w") as f:
            json.dump(config, f)
        app, _ = server.create_app(path)
        client = app.test_client()
        for url in (
            f"/.well-known/oauth-authorization-server/{FRONTEND_ID}",
            f"/{FRONTEND_ID}/.well-known/openid-configuration",
        ):
            assert client.get(url).get_json()["issuer"] == f"https://as.test/{FRONTEND_ID}"
        assert client.post(f"/{FRONTEND_ID}/token", data={}).status_code == 400
        assert client.get("/static/../config.yaml").status_code == 404

    def test_issuer_with_a_trailing_slash(self, tmp_path):
        # The backend publishes <base_url without the slash>/<frontend id>.
        path = _test_config(tmp_path)
        with open(path) as f:
            config = json.load(f)
        config["domain"] = "as.test"
        config["op"]["server_info"]["issuer"] = "https://{domain}/"
        with open(path, "w") as f:
            json.dump(config, f)
        app, _ = server.create_app(path)
        metadata = app.test_client().get(f"/.well-known/oauth-authorization-server/{FRONTEND_ID}").get_json()
        assert metadata["issuer"] == f"https://as.test/{FRONTEND_ID}"
        assert metadata["token_endpoint"] == f"https://as.test/{FRONTEND_ID}/token"
        assert metadata["jwks_uri"] == "https://as.test/static/jwks.json"

    def test_no_routes_outside_the_issuer(self, client):
        # No catch-all static route: the old endpoints at the root are gone for every method.
        for method, url in (("POST", "/token"), ("POST", "/pushed_authorization"), ("PUT", "/x"), ("GET", "/jwks.json")):
            assert client.open(url, method=method).status_code == 404, (method, url)
        assert client.get(PREFIX + "/static/jwks.json").status_code == 200
