"""Endpoints of views.py: token grants, introspection, authorization,
/verify/user, /preauth_generate, discovery, static files and the
service_endpoint glue around the idpy-oidc endpoints."""

import datetime
import json
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptojwt.exception import VerificationError
from flask import make_response
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.exception import ClientAuthenticationError, FailedAuthentication

import application
import views
from conftest import FE, FRONTEND_ID, PREFIX, BACKEND_API_KEY
from test_security import (
    CHALLENGE,
    CLIENT_ID,
    REDIRECT_URI,
    VERIFIER,
    TestWalletAttestationRequired,
    _authorize,
    _dpop_proof,
    _jkt,
    _with_dpop,
)

PREAUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
API_KEY = {"X-Api-Key": BACKEND_API_KEY}


@pytest.fixture
def key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def relaxed(app):
    """PAR, DPoP, wallet attestation and PKCE switched off (as in test_security)."""
    from security import configure_client_authentication

    app.require_pushed_authorization_requests = False
    app.require_dpop = False
    configure_client_authentication(app, require_wallet_attestation=False)
    app.server.get_context().add_on["pkce"]["essential"] = False
    return app


def _par(client, headers=None, **extra):
    return TestWalletAttestationRequired()._par(client, headers, **extra)


def _code(client, **extra):
    """An authorization code for the test wallet."""
    mine = _authorize(client, **extra)
    location = client.get(
        PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]}
    ).headers["Location"]
    return parse_qs(urlsplit(location).query)["code"][0]


def _code_tokens(client, wia, key):
    response = client.post(
        FE + "/token",
        data={
            "grant_type": "authorization_code",
            "code": _code(client),
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": VERIFIER,
        },
        headers={**wia(), "DPoP": _dpop_proof(key)},
    )
    assert response.status_code == 200, response.data
    return response.get_json()


def _refresh(client, wia, refresh_token, key=None, dpop_header=True):
    headers = wia()
    if dpop_header:
        headers["DPoP"] = _dpop_proof(key or ec.generate_private_key(ec.SECP256R1()))
    data = {"grant_type": "refresh_token", "client_id": CLIENT_ID}
    if refresh_token is not None:
        data["refresh_token"] = refresh_token
    return client.post(FE + "/token", data=data, headers=headers)


def _introspect(client, token, headers=API_KEY):
    return client.post(PREFIX + "/introspection", data={"token": token}, headers=headers)


class TestRefreshTokenGrant:
    def test_refresh_issues_new_tokens_bound_to_the_same_key(self, client, wia, key):
        first = _code_tokens(client, wia, key)
        response = _refresh(client, wia, first["refresh_token"], key)
        assert response.status_code == 200, response.data
        body = response.get_json()
        assert body["token_type"] == "DPoP"
        assert body["access_token"] != first["access_token"]
        assert _introspect(client, body["access_token"]).get_json()["cnf"] == {"jkt": _jkt(key)}
        session = application.request_manager.get_request_by_refresh_token(body["refresh_token"])
        assert session is not None and session.access_token == body["access_token"]

    def test_used_refresh_token_is_no_longer_accepted(self, client, wia, key):
        first = _code_tokens(client, wia, key)
        assert _refresh(client, wia, first["refresh_token"], key).status_code == 200
        again = _refresh(client, wia, first["refresh_token"], key)
        assert again.status_code == 400
        assert again.get_json()["error"] == "invalid_grant"

    # RFC 6749 section 5.2: these tokens reach idpy-oidc (the session still
    # knows them), which must answer invalid_grant so the wallet re-authorizes.
    def test_expired_refresh_token_is_invalid_grant(self, client, wia, key, monkeypatch):
        first = _code_tokens(client, wia, key)
        monkeypatch.setattr("idpyoidc.server.token.jwt_token.is_expired", lambda *a, **k: True)
        response = _refresh(client, wia, first["refresh_token"], key)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"

    def test_revoked_refresh_token_is_invalid_grant(self, app, client, wia, key):
        first = _code_tokens(client, wia, key)
        _mngr = app.server.get_context().session_manager
        _info = _mngr.get_session_info_by_token(
            first["refresh_token"], handler_key="refresh_token", grant=True
        )
        _info["grant"].get_token(first["refresh_token"]).revoke()
        response = _refresh(client, wia, first["refresh_token"], key)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"

    def test_refresh_keeps_the_session_for_the_refresh_token_lifetime(self, app, client, wia, key):
        first = _code_tokens(client, wia, key)
        session = application.request_manager.get_request_by_refresh_token(first["refresh_token"])
        _lifetime = app.server.get_context().authz.grant_config["usage_rules"]["refresh_token"][
            "expires_in"
        ]
        remaining = session.expiry_time - datetime.datetime.now(datetime.timezone.utc)
        assert remaining.total_seconds() >= _lifetime - 60

    def test_refresh_with_another_dpop_key_is_refused(self, client, wia, key):
        first = _code_tokens(client, wia, key)
        response = _refresh(client, wia, first["refresh_token"])  # new key
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"
        # The wallet holding the bound key can still refresh.
        assert _refresh(client, wia, first["refresh_token"], key).status_code == 200

    def test_refresh_of_a_bound_token_without_proof_is_refused(self, app, client, wia, key):
        first = _code_tokens(client, wia, key)
        app.require_dpop = False
        response = _refresh(client, wia, first["refresh_token"], dpop_header=False)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"

    def test_unknown_refresh_token(self, client, wia):
        response = _refresh(client, wia, "unknown")
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_grant"}

    def test_missing_refresh_token(self, client, wia):
        response = _refresh(client, wia, None)
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_request", "error_description": "missing refresh_token"}

    def test_refresh_rejected_by_the_token_endpoint_is_passed_on(self, client, wia, key):
        """Without the wallet attestation the token endpoint answers 400 invalid_client."""
        first = _code_tokens(client, wia, key)
        response = client.post(
            FE + "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": CLIENT_ID},
            headers={"DPoP": _dpop_proof(key)},
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_client"


PAR_HTU = "https://issuer.eudiw.dev/oidc/fe/pushed_authorization"


class TestDpopKeyFromAuthorizationRequest:
    """RFC 9449 section 10: a key named in the authorization request (dpop_jkt,
    or the DPoP proof at PAR, section 10.1) is the only one the code redeems with."""

    def _redeem(self, client, wia, code, key):
        return client.post(
            FE + "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
            headers={**wia(), "DPoP": _dpop_proof(key)},
        )

    def _code_from_par(self, client, wia, headers):
        args = {**TestWalletAttestationRequired.PAR, "code_challenge": CHALLENGE, "code_challenge_method": "S256"}
        pushed = client.post(FE + "/pushed_authorization", data=args, headers={**wia(), **headers})
        assert pushed.status_code == 201, pushed.data
        response = client.get(
            FE + "/authorization", query_string={"client_id": CLIENT_ID, "request_uri": pushed.get_json()["request_uri"]}
        )
        assert response.status_code == 302, response.data
        mine = {k: v[0] for k, v in parse_qs(urlsplit(response.headers["Location"]).query).items()}
        location = client.get(
            PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]}
        ).headers["Location"]
        return parse_qs(urlsplit(location).query)["code"][0]

    def test_code_bound_with_dpop_jkt_needs_that_key(self, client, wia, key):
        code = _code(client, dpop_jkt=_jkt(key))
        response = self._redeem(client, wia, code, ec.generate_private_key(ec.SECP256R1()))
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"
        # The refused attempt did not use up the code.
        response = self._redeem(client, wia, code, key)
        assert response.status_code == 200, response.data
        assert response.get_json()["token_type"] == "DPoP"

    def test_dpop_proof_at_par_binds_the_code(self, client, wia, key):
        code = self._code_from_par(client, wia, {"DPoP": _dpop_proof(key, htu=PAR_HTU)})
        response = self._redeem(client, wia, code, ec.generate_private_key(ec.SECP256R1()))
        assert response.get_json()["error"] == "invalid_dpop_proof"
        assert self._redeem(client, wia, code, key).status_code == 200

    def test_par_proof_must_match_dpop_jkt(self, client, wia, key):
        args = {**TestWalletAttestationRequired.PAR, "dpop_jkt": _jkt(ec.generate_private_key(ec.SECP256R1()))}
        response = client.post(
            FE + "/pushed_authorization", data=args, headers={**wia(), "DPoP": _dpop_proof(key, htu=PAR_HTU)}
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"

    def test_invalid_proof_at_par_is_refused(self, client, wia, key):
        # A proof for /token is not one for /pushed_authorization.
        response = client.post(
            FE + "/pushed_authorization", data=TestWalletAttestationRequired.PAR, headers={**wia(), "DPoP": _dpop_proof(key)}
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"


def test_pushed_authorization_details_reach_the_token_response(client, wia, key):
    # The authorization endpoint resolves the pushed request (RFC 9126 section 4):
    # its authorization_details are returned with the token (RFC 9396 section 6).
    details = [{"type": "openid_credential", "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc"}]
    code = _code(client, authorization_details=json.dumps(details))
    response = TestDpopKeyFromAuthorizationRequest()._redeem(client, wia, code, key)
    assert response.status_code == 200, response.data
    assert response.get_json()["authorization_details"] == details

class TestTokenErrors:
    def test_unsupported_grant_type(self, client):
        response = client.post(FE + "/token", data={"grant_type": "password"}, headers=_with_dpop())
        assert response.status_code == 400
        assert response.get_json()["error"] == "unsupported_grant_type"

    def test_missing_grant_type(self, client):
        """RFC 6749 section 5.2: a missing required parameter is invalid_request."""
        response = client.post(FE + "/token", data={}, headers=_with_dpop())
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_authorization_code_missing(self, client):
        response = client.post(FE + "/token", data={"grant_type": "authorization_code"}, headers=_with_dpop())
        assert response.status_code == 400
        assert response.get_json()["error_description"] == "missing code"

    def test_authorization_code_unknown(self, client):
        response = client.post(
            FE + "/token", data={"grant_type": "authorization_code", "code": "nope"}, headers=_with_dpop()
        )
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_grant"}

    @pytest.mark.parametrize(
        "data, description",
        [
            ({}, "missing pre-authorized_code"),
            ({"pre-authorized_code": "x"}, "missing tx_code"),
        ],
    )
    def test_pre_authorized_code_missing_parameters(self, client, data, description):
        response = client.post(FE + "/token", data={"grant_type": PREAUTH_GRANT, **data}, headers=_with_dpop())
        assert response.status_code == 400
        assert response.get_json()["error_description"] == description

    def test_malformed_dpop_proof(self, client, wia):
        """The proof is validated by the idpy-oidc DPoP add-on, on an otherwise valid request."""
        code = client.post(PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers=API_KEY).get_json()
        response = client.post(
            FE + "/token",
            data={"grant_type": PREAUTH_GRANT, "pre-authorized_code": code["preauth_code"], "tx_code": str(code["tx_code"])},
            headers={**wia(), "DPoP": "not-a-jwt"},
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"


class TestIntrospection:
    def test_missing_key(self, client):
        response = client.post(PREFIX + "/introspection", data={"token": "x"})
        assert response.status_code == 401
        assert response.get_json()["error"] == "unauthorized"

    def test_wrong_key(self, client):
        assert _introspect(client, "x", {"X-Api-Key": "wrong"}).status_code == 401

    @pytest.mark.parametrize("configured", [None, "", "secret"])
    def test_unconfigured_key_fails_closed(self, app, client, configured):
        app.backend_api_key = configured
        response = _introspect(client, "x")
        assert response.status_code == 503
        assert response.get_json()["error"] == "service_unavailable"

    def test_unknown_token_is_inactive(self, client):
        response = _introspect(client, "garbage")
        assert response.status_code == 200
        assert response.get_json() == {"active": False}
        assert response.headers["Cache-Control"] == "no-store"

    def test_active_dpop_token_reports_cnf(self, client, wia, key):
        tokens = _code_tokens(client, wia, key)
        body = _introspect(client, tokens["access_token"]).get_json()
        assert body["active"] is True
        assert body["cnf"] == {"jkt": _jkt(key)}
        assert body["client_id"] == CLIENT_ID

    def test_bearer_token_has_no_cnf(self, relaxed, client):
        code = client.post(PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers=API_KEY).get_json()
        token = client.post(
            FE + "/token",
            data={"grant_type": PREAUTH_GRANT, "pre-authorized_code": code["preauth_code"], "tx_code": str(code["tx_code"])},
        ).get_json()["access_token"]
        body = _introspect(client, token).get_json()
        assert body["active"] is True and "cnf" not in body

    def test_inactive_token_has_no_cnf(self, client):
        body = _introspect(client, "garbage").get_json()
        assert body == {"active": False}

    def test_endpoint_error_is_passed_on(self, client):
        """A request the introspection endpoint rejects keeps its status."""
        response = client.post(PREFIX + "/introspection", data={}, headers=API_KEY)
        assert response.status_code == 400
        assert "cnf" not in response.get_json()


class TestAuthorizationEndpoint:
    def test_empty_request_uri(self, client):
        response = client.get(FE + "/authorization", query_string={"request_uri": ""})
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_unknown_request_uri(self, client):
        response = client.get(FE + "/authorization", query_string={"client_id": CLIENT_ID, "request_uri": "urn:unknown"})
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request_uri"

    def test_par_required(self, client):
        response = client.get(FE + "/authorization", query_string={"client_id": CLIENT_ID})
        assert response.status_code == 400
        assert "pushed authorization request" in response.get_json()["error_description"]

    def test_par_without_state(self, client, wia):
        """The state is optional; the redirect still carries the session."""
        pushed = client.post(
            FE + "/pushed_authorization",
            data={k: v for k, v in TestWalletAttestationRequired.PAR.items()},
            headers=wia(),
        )
        request_uri = pushed.get_json()["request_uri"]
        response = client.get(FE + "/authorization", query_string={"client_id": CLIENT_ID, "request_uri": request_uri})
        assert response.status_code == 302
        assert "session_token=" in response.headers["Location"]

    def test_par_frontend_id_and_authorization_details_reach_the_backend(self, app, client):
        # The frontend is the one whose issuer the request was pushed to; a
        # frontend_id parameter is ignored.
        details = [{"type": "openid_credential", "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc"}]
        query = _authorize(client, frontend_id="fe-1", authorization_details=json.dumps(details))
        assert query["frontend_id"] == FRONTEND_ID
        assert json.loads(query["authorization_details"]) == details
        context = app.server.get_context()
        from cryptojwt.jwt import JWT

        claims = JWT(context.keyjar, allowed_sign_algs=["ES256"]).unpack(query["session_token"])
        assert claims["iss"] == context.issuer
        assert claims["frontend_id"] == FRONTEND_ID
        assert claims["authorization_details"] == details

    @pytest.mark.parametrize(
        "exc, description",
        [
            (requests.exceptions.ConnectionError("down"), "internal_service_unavailable"),
            (RuntimeError("boom"), "unhandled_exception"),
        ],
    )
    def test_internal_failure_redirects_an_error_to_the_wallet(self, client, wia, monkeypatch, exc, description):
        pushed = _par(client, wia())
        request_uri = pushed.get_json()["request_uri"]

        def fail(*args, **kwargs):
            raise exc

        monkeypatch.setattr(views, "service_endpoint", fail)
        response = client.get(FE + "/authorization", query_string={"client_id": CLIENT_ID, "request_uri": request_uri})
        assert response.status_code == 302
        location = response.headers["Location"]
        assert location.startswith(REDIRECT_URI + "?")
        assert parse_qs(urlsplit(location).query) == {
            "error": ["server_error"],
            "error_description": [description],
        }


class TestNonPushedAuthorization:
    ARGS = {"client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "response_type": "code"}

    @pytest.mark.parametrize("missing", ["client_id", "redirect_uri", "response_type"])
    def test_missing_parameters(self, relaxed, client, missing):
        args = {k: v for k, v in self.ARGS.items() if k != missing}
        response = client.get(FE + "/authorization", query_string=args)
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_request", "error_description": "Missing required parameters"}

    def test_store_failure_is_500(self, relaxed, client, monkeypatch):
        def fail(**kwargs):
            raise RuntimeError("full")

        monkeypatch.setattr(application.request_manager, "add_request", fail)
        response = client.get(FE + "/authorization", query_string=self.ARGS)
        assert response.status_code == 500
        assert response.get_json() == {"error": "server_error", "error_description": "Failed to process request"}

    def test_pkce_and_issuer_state_are_kept(self, relaxed, client):
        response = client.get(
            FE + "/authorization",
            query_string={**self.ARGS, "code_challenge": CHALLENGE, "code_challenge_method": "S256",
                          "issuer_state": "offer-1"},
        )
        assert response.status_code == 302
        query = parse_qs(urlsplit(response.headers["Location"]).query)
        assert "scope" not in query
        stored = application.request_manager.get_request(query["session_id"][0])
        assert stored.code_challenge == CHALLENGE and stored.issuer_state == "offer-1"

    def test_authorization_details_reach_the_backend(self, relaxed, client):
        details = json.dumps([{"type": "openid_credential", "credential_configuration_id": "x"}])
        response = client.get(FE + "/authorization", query_string={**self.ARGS, "authorization_details": details})
        assert response.status_code == 302
        query = parse_qs(urlsplit(response.headers["Location"]).query)
        stored = application.request_manager.get_request(query["session_id"][0])
        assert stored.authorization_details == details
        assert "authorization_details" in query


class TestVerifyUser:
    def test_without_token_is_500(self, client):
        response = client.get(PREFIX + "/verify/user", query_string={"username": "x"})
        assert response.status_code == 500
        assert response.data == b"Internal Server Error"

    def test_unknown_session_is_a_mismatch(self, client):
        mine = _authorize(client)
        response = client.get(PREFIX + "/verify/user", query_string={"token": mine["token"], "username": "unknown"})
        assert response.status_code == 400
        assert json.loads(response.data)["error_description"] == "Session mismatch"

    def test_failure_with_jws_token_redirects_the_error(self, client):
        mine = _authorize(client)
        response = client.get(PREFIX + "/verify/user", query_string={"jws_token": mine["token"]})
        assert response.status_code == 302
        location = response.headers["Location"]
        assert location.startswith(REDIRECT_URI + "?")
        assert parse_qs(urlsplit(location).query) == {
            "error": ["invalid_request"],
            "error_description": ["Authentication verification Error"],
            "state": ["st"],  # the authorization request's state (RFC 6749 4.1.2.1)
        }

    def test_failure_with_invalid_jws_token(self, client):
        response = client.get(PREFIX + "/verify/user", query_string={"jws_token": "forged"})
        assert response.status_code == 400
        assert json.loads(response.data)["error_description"] == "Cookie Lost"

    def test_error_redirect_carries_the_state(self, client):
        mine = _authorize(client)  # state=st
        location = client.get(PREFIX + "/verify/user", query_string={"jws_token": mine["token"]}).headers["Location"]
        assert parse_qs(urlsplit(location).query).get("state") == ["st"]

    def test_failed_authentication_renders_the_error_page(self, client, monkeypatch):
        def fail(authn_method):
            raise FailedAuthentication("Wrong user")

        monkeypatch.setattr(views, "verify", fail)
        response = client.get(PREFIX + "/verify/user")
        assert response.status_code == 200
        assert b"Wrong user" in response.data

    def _patch_authz_part2(self, app, monkeypatch, response_args):
        endpoint = app.server.get_endpoint("authorization")
        monkeypatch.setattr(endpoint, "authz_part2", lambda request, session_id: {"response_args": response_args})

    def test_authz_part2_error_is_400(self, app, client, monkeypatch):
        mine = _authorize(client)
        self._patch_authz_part2(app, monkeypatch, ResponseMessage(error="access_denied"))
        response = client.get(PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]})
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "access_denied"}

    def test_no_code_issued_is_500(self, app, client, monkeypatch):
        mine = _authorize(client)
        self._patch_authz_part2(app, monkeypatch, ResponseMessage(state="st"))
        response = client.get(PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]})
        assert response.status_code == 500
        assert json.loads(response.data)["error"] == "server_error"

    def test_form_post_error_without_response_args_is_500(self, app, client, monkeypatch):
        # response_mode=form_post errors carry only response_msg (upstream #166).
        mine = _authorize(client)
        endpoint = app.server.get_endpoint("authorization")
        monkeypatch.setattr(endpoint, "authz_part2", lambda request, session_id: {"response_msg": "<form/>"})
        response = client.get(PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]})
        assert response.status_code == 500
        assert json.loads(response.data)["error"] == "server_error"

    def test_code_is_recorded_for_the_session(self, client):
        mine = _authorize(client)
        location = client.get(
            PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]}
        ).headers["Location"]
        code = parse_qs(urlsplit(location).query)["code"][0]
        assert application.request_manager.get_request_by_code(code).session_id == mine["session_id"]


class TestPreauthGenerate:
    def _generate(self, client, **data):
        return client.post(PREFIX + "/preauth_generate", data={"frontend_id": FRONTEND_ID, **data}, headers=API_KEY)

    def test_without_scope(self, client):
        body = self._generate(client).get_json()
        stored = application.request_manager.get_request(body["session_id"])
        assert stored.scope is None and stored.tx_code == body["tx_code"]
        assert application.request_manager.get_request_by_preauth_code_ref(body["preauth_code"]) is stored

    def test_registration_failure(self, client, monkeypatch):
        monkeypatch.setattr(
            views, "dynamic_registration",
            lambda **kw: (views._registration_error("client registration failed"), views._no_restore),
        )
        response = self._generate(client, scope="x")
        assert response.status_code == 400
        assert response.get_json()["error_description"] == "client registration failed"

    @pytest.mark.parametrize(
        "exc, description",
        [
            (requests.exceptions.Timeout("slow"), "internal_service_unavailable"),
            (RuntimeError("boom"), "unhandled_exception"),
        ],
    )
    def test_internal_failure_is_json_not_a_redirect(self, client, monkeypatch, exc, description):
        """The internal client's "preauth" redirect URI is never a redirect target."""
        def fail(*args, **kwargs):
            raise exc

        monkeypatch.setattr(views, "service_endpoint", fail)
        response = self._generate(client, scope="x")
        assert response.status_code == 500
        assert "Location" not in response.headers
        assert response.get_json() == {"error": "server_error", "error_description": description}

    def test_response_without_data(self, client, monkeypatch):
        monkeypatch.setattr(views, "service_endpoint", lambda *a, **kw: object())
        response = self._generate(client, scope="x")
        assert response.status_code == 500
        assert response.get_json()["error_description"] == "invalid_internal_response"

    def test_store_failure_is_500(self, client, monkeypatch):
        def fail(**kwargs):
            raise RuntimeError("full")

        monkeypatch.setattr(application.request_manager, "add_request", fail)
        response = self._generate(client, scope="x")
        assert response.status_code == 500
        assert response.get_json() == {"error": "Failed to process request"}

    def _bad_jws(self, monkeypatch):
        monkeypatch.setattr(
            views, "service_endpoint", lambda *a, **kw: make_response(json.dumps({"jws": "garbage"}), 200)
        )

    def test_unreadable_authentication_token_is_500(self, client, monkeypatch):
        self._bad_jws(monkeypatch)
        response = self._generate(client, scope="x")
        assert response.status_code == 500
        assert response.data == b"Internal Server Error"

    def test_unreadable_authentication_token_with_jws_token(self, client, monkeypatch):
        self._bad_jws(monkeypatch)
        response = client.post(PREFIX + "/preauth_generate?jws_token=forged", data={"scope": "x", "frontend_id": FRONTEND_ID}, headers=API_KEY)
        assert response.status_code == 400
        assert json.loads(response.data)["error_description"] == "Cookie Lost"

    def test_authz_part2_error_is_400(self, app, client, monkeypatch):
        endpoint = app.server.get_endpoint("authorization")
        monkeypatch.setattr(
            endpoint, "authz_part2",
            lambda request, session_id: {"response_args": ResponseMessage(error="invalid_scope")},
        )
        response = self._generate(client, scope="x")
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "invalid_scope"}

    @pytest.mark.parametrize("result", [{"response_args": ResponseMessage(state="st")}, {"response_msg": "<form/>"}])
    def test_no_code_issued_is_500(self, app, client, monkeypatch, result):
        # No code (or a form_post error without response_args) must not crash (upstream #166).
        endpoint = app.server.get_endpoint("authorization")
        monkeypatch.setattr(endpoint, "authz_part2", lambda request, session_id: result)
        response = self._generate(client, scope="x")
        assert response.status_code == 500
        assert json.loads(response.data)["error"] == "server_error"


class TestDynamicRegistration:
    @staticmethod
    def _register(app, client_id, uri, internal=False):
        with app.test_request_context("/"):
            error, restore = views.dynamic_registration(client_id, uri, internal=internal)
            return (None if error is None else (error.status_code, json.loads(error.data))), restore

    @pytest.mark.parametrize("client_id", [None, "", 42])
    def test_client_id_required(self, app, client_id):
        error, _ = self._register(app, client_id, REDIRECT_URI)
        assert error == (400, {"error": "invalid_request", "error_description": "client_id is required"})

    def test_internal_only_accepts_the_preauth_placeholder(self, app):
        error, _ = self._register(app, "eudiw-abca", REDIRECT_URI, internal=True)
        assert error[0] == 400 and error[1]["error_description"] == "invalid redirect_uri"

    def test_redirect_uri_the_registration_endpoint_refuses(self, app, monkeypatch):
        registration = app.server.get_endpoint("registration")

        def refuse(request):
            raise ValueError("bad uri")

        monkeypatch.setattr(registration, "verify_redirect_uris", refuse)
        error, _ = self._register(app, "wallet-x", REDIRECT_URI)
        assert error[1]["error_description"] == "invalid redirect_uri"
        assert "wallet-x" not in app.server.get_context().cdb

    @pytest.mark.parametrize("failure", ["raises", "error_message"])
    def test_failed_registration_removes_the_client_entry(self, app, monkeypatch, failure):
        """A half-registered client must not stay in the client database."""
        registration = app.server.get_endpoint("registration")
        cdb = app.server.get_context().cdb

        def register(client_id, redirect_uri):
            cdb[client_id] = {"client_id": client_id}  # partially written
            if failure == "raises":
                raise RuntimeError("storage failure")
            return ResponseMessage(error="invalid_client_metadata", error_description="nope")

        monkeypatch.setattr(registration, "process_request_authorization", register)
        error, restore = self._register(app, "wallet-y", REDIRECT_URI)
        assert error == (400, {"error": "invalid_request", "error_description": "client registration failed"})
        assert "wallet-y" not in cdb
        assert restore() is None

    def test_restore_after_the_client_is_gone(self, app):
        error, restore = self._register(app, "wallet-z", REDIRECT_URI)
        assert error is None
        del app.server.get_context().cdb["wallet-z"]
        restore()
        assert "wallet-z" not in app.server.get_context().cdb


class TestParEndpoint:
    @pytest.mark.parametrize("missing", ["client_id", "redirect_uri", "response_type"])
    def test_missing_parameters(self, client, wia, missing):
        data = {k: v for k, v in TestWalletAttestationRequired.PAR.items() if k != missing}
        response = client.post(FE + "/pushed_authorization", data=data, headers=wia())
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_request", "error_description": "Missing required parameters"}

    def test_invalid_authorization_details(self, client, wia):
        response = _par(client, wia(), authorization_details="{not json")
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_request", "error_description": "Invalid authorization_details JSON"}

    def test_endpoint_exception_is_500_and_registers_nothing(self, app, client, monkeypatch):
        def fail(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(views, "service_endpoint", fail)
        response = _par(client, client_id="wallet-boom")
        assert response.status_code == 500
        assert "wallet-boom" not in app.server.get_context().cdb

    def test_store_failure_is_500(self, client, wia, monkeypatch):
        def fail(**kwargs):
            raise RuntimeError("full")

        monkeypatch.setattr(application.request_manager, "add_request", fail)
        response = _par(client, wia())
        assert response.status_code == 500
        assert response.get_json() == {"error": "server_error", "error_description": "Failed to process request"}

    def test_frontend_id_is_stored(self, client, wia):
        # The path's frontend, never a frontend_id parameter.
        request_uri = _par(client, wia(), frontend_id="fe-9").get_json()["request_uri"]
        assert application.request_manager.get_request_by_uri(request_uri).frontend_id == FRONTEND_ID


class TestDiscoveryAndStatic:
    @pytest.mark.parametrize("service", ["openid-configuration", "oauth-authorization-server"])
    def test_metadata(self, client, service):
        response = client.get(f"{FE}/.well-known/{service}")
        assert response.status_code == 200
        doc = response.get_json()
        assert doc["require_pushed_authorization_requests"] is True
        assert doc["token_endpoint_auth_methods_supported"] == ["attest_jwt_client_auth"]

    def test_both_metadata_documents_are_the_same(self, client):
        assert (
            client.get(FE + "/.well-known/openid-configuration").get_json()
            == client.get(FE + "/.well-known/oauth-authorization-server").get_json()
        )

    def test_issuer_and_endpoints_are_the_frontends(self, client):
        doc = client.get(FE + "/.well-known/oauth-authorization-server").get_json()
        issuer = "https://issuer.eudiw.dev" + FE
        assert doc["issuer"] == issuer
        assert doc["pushed_authorization_request_endpoint"] == issuer + "/pushed_authorization"
        assert doc["authorization_endpoint"] == issuer + "/authorization"
        assert doc["token_endpoint"] == issuer + "/token"
        assert doc["jwks_uri"] == "https://issuer.eudiw.dev/oidc/static/jwks.json"
        assert doc["authorization_response_iss_parameter_supported"] is True

    def test_values_in_force(self, client):
        # Upstream #6 and frontend #14: what the server enforces, not a static file.
        doc = client.get(FE + "/.well-known/oauth-authorization-server").get_json()
        assert doc["dpop_signing_alg_values_supported"] == [
            "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"
        ]
        assert doc["token_endpoint_auth_methods_supported"] == ["attest_jwt_client_auth"]
        assert doc["code_challenge_methods_supported"] == ["S256"]
        assert doc["pre-authorized_grant_anonymous_access_supported"] is False

    def test_without_pkce_or_client_authn(self, app, client, monkeypatch):
        monkeypatch.delitem(app.server.get_context().add_on, "pkce")
        monkeypatch.setattr(app.server.get_endpoint("token"), "client_authn_method", [])
        doc = client.get(FE + "/.well-known/openid-configuration").get_json()
        assert "code_challenge_methods_supported" not in doc
        assert "token_endpoint_auth_methods_supported" not in doc

    @pytest.mark.parametrize(
        "path",
        [
            "/.well-known/oauth-authorization-server/oidc/fe2",
            "/.well-known/openid-configuration/oidc/fe2",
            "/oidc/fe2/.well-known/oauth-authorization-server",
            "/oidc/fe2/.well-known/openid-configuration",
        ],
    )
    def test_every_discovery_url(self, client, path):
        # RFC 8414 inserts the well-known path after the host; OpenID Connect
        # Discovery appends it to the issuer. Both forms of both documents.
        response = client.get(path)
        assert response.status_code == 200
        assert response.get_json()["issuer"] == "https://issuer.eudiw.dev/oidc/fe2"

    @pytest.mark.parametrize(
        "path",
        [
            "/.well-known/oauth-authorization-server/oidc/unknown",
            "/oidc/unknown/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/oidc",
            "/oidc/.well-known/openid-configuration",
            "/.well-known/openid-configuration",
            FE + "/.well-known/webfinger",
            FE + "/.well-known/security.txt",
        ],
    )
    def test_unknown_frontend_or_service(self, client, path):
        assert client.get(path).status_code == 404

    def test_unknown_frontend_endpoints(self, client):
        assert client.post(PREFIX + "/unknown/pushed_authorization").status_code == 404
        assert client.post(PREFIX + "/unknown/token").status_code == 404
        assert client.get(PREFIX + "/unknown/authorization").status_code == 404

    def test_index(self, client):
        assert client.get(PREFIX + "/").status_code == 200

    @pytest.fixture
    def published_jwks(self, app):
        """A JWKS file in static/ (the real one is generated at start-up and not in git)."""
        import os
        import uuid

        name = f"test-{uuid.uuid4().hex}.json"
        path = os.path.join(app.root_path, "static", name)
        with open(path, "w") as f:
            json.dump({"keys": []}, f)
        yield name
        os.remove(path)

    def test_static_file(self, client, published_jwks):
        response = client.get(f"{PREFIX}/static/{published_jwks}")
        assert response.status_code == 200
        assert "keys" in json.loads(response.data)

    def test_static_path_traversal_refused(self, client):
        assert client.get(PREFIX + "/static/../config.yaml").status_code == 404

    def test_keys_serves_published_jwks(self, client, published_jwks):
        response = client.get(f"{PREFIX}/keys/{published_jwks}")
        assert response.status_code == 200
        assert response.mimetype == "application/json"
        assert "keys" in response.get_json()


class FakeEndpoint:
    """Stand-in for an idpy-oidc endpoint, to drive service_endpoint's branches."""

    name = "fake"
    response_placement = "body"

    def __init__(self, parse=None, process=None, info=None):
        self.parse, self.process, self.info = parse, process, info
        self.parsed = None

    def parse_request(self, args, http_info=None, **kwargs):
        self.parsed = args
        if isinstance(self.parse, Exception):
            raise self.parse
        return self.parse if self.parse is not None else args

    def process_request(self, request, http_info=None):
        if isinstance(self.process, Exception):
            raise self.process
        return self.process if self.process is not None else {"response_args": {"ok": True}}

    def do_response(self, request=None, error="", **args):
        return self.info or {"response": json.dumps({"ok": True}), "http_headers": []}


class TestServiceEndpoint:
    def _call(self, app, endpoint, method="POST", **request_kw):
        with app.test_request_context("/x", method=method, **request_kw):
            return views.service_endpoint(endpoint)

    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_client_authentication_error_is_400(self, app, method):
        response = self._call(app, FakeEndpoint(parse=ClientAuthenticationError("bad wia")), method)
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "invalid_client", "error_description": "bad wia"}

    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_parse_error_is_400(self, app, method):
        response = self._call(app, FakeEndpoint(parse=ValueError("bad input")), method)
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "invalid_request", "error_description": "bad input"}

    def test_raw_body_is_parsed(self, app):
        endpoint = FakeEndpoint()
        self._call(app, endpoint, data="token=abc", content_type="text/plain")
        assert endpoint.parsed == "token=abc"

    @pytest.mark.parametrize("method, content_type", [("GET", None), ("POST", "application/json")])
    def test_error_message_from_parsing(self, app, method, content_type):
        response = self._call(app, FakeEndpoint(parse=ResponseMessage(error="invalid_scope")), method)
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_scope"
        if content_type:
            assert response.headers["Content-type"] == content_type

    def test_verification_error_means_inactive(self, app):
        endpoint = FakeEndpoint(process=VerificationError("bad signature"))
        captured = {}

        def do_response(request=None, error="", **args):
            captured.update(args)
            return {"response": args["response_args"].to_json(), "http_headers": []}

        endpoint.do_response = do_response
        response = self._call(app, endpoint, data={"token": "t"})
        assert response.status_code == 200
        assert json.loads(response.data) == {"active": False}

    def test_processing_error_is_400(self, app):
        response = self._call(app, FakeEndpoint(process=RuntimeError("broken")), data={"a": "b"})
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "invalid_request", "error_description": "broken"}

    def test_redirect_location(self, app):
        response = self._call(app, FakeEndpoint(process={"redirect_location": "https://w.test/x"}), "GET")
        assert response.status_code == 302 and response.headers["Location"] == "https://w.test/x"

    def test_http_response(self, app):
        response = self._call(app, FakeEndpoint(process={"http_response": "<html/>"}), "GET")
        assert response.status_code == 200 and response.data == b"<html/>"

    @pytest.mark.parametrize(
        "placement, info, status, location",
        [
            ("body", {"response": "{}", "http_headers": [("X-A", "1")], "response_code": 401}, 401, None),
            ("body", {"response": "{}", "http_headers": [("X-A", "1")]}, 400, None),
            ("url", {"response": "https://w.test/cb?error=x", "http_headers": [("X-A", "1")]}, 302,
             "https://w.test/cb?error=x"),
        ],
    )
    def test_error_responses(self, app, placement, info, status, location):
        endpoint = FakeEndpoint(process={"error": "x"}, info=info)
        endpoint.response_placement = placement
        response = self._call(app, endpoint, "GET")
        assert response.status_code == status
        assert response.headers["X-A"] == "1"
        assert response.headers.get("Location") == location

    def test_url_placement_from_the_response_info(self, app):
        info = {"response": "https://w.test/cb?code=c", "http_headers": [], "response_placement": "url"}
        response = self._call(app, FakeEndpoint(info=info), "GET")
        assert response.status_code == 302 and response.headers["Location"] == "https://w.test/cb?code=c"

    @pytest.mark.parametrize(
        "cookie",
        [
            {"name": "a", "value": "1"},
            [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}],
        ],
    )
    def test_cookies_are_secure(self, app, cookie):
        info = {"response": "{}", "http_headers": [], "cookie": cookie}
        response = self._call(app, FakeEndpoint(info=info), "GET")
        set_cookies = response.headers.getlist("Set-Cookie")
        assert len(set_cookies) == (1 if isinstance(cookie, dict) else 2)
        for header in set_cookies:
            assert "Secure" in header and "HttpOnly" in header and "SameSite=Lax" in header and "Path=/" in header


class TestErrorRedirect:
    def test_registered_uri_with_a_query_keeps_it(self, app, client, wia):
        uri = "https://wallet.test/cb?x=1"
        assert _par(client, wia(), redirect_uri=uri).status_code in (200, 201)
        with app.test_request_context("/"):
            response = views.auth_error_redirect(uri, "access_denied", "denied", client_id=CLIENT_ID)
        assert response.status_code == 302
        assert parse_qs(urlsplit(response.headers["Location"]).query) == {
            "x": ["1"], "error": ["access_denied"], "error_description": ["denied"],
        }

    def test_unknown_client_gets_json(self, app):
        with app.test_request_context("/"):
            response = views.auth_error_redirect(REDIRECT_URI, "access_denied", client_id="nobody")
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "access_denied"}


class TestAuthenticationErrorRedirect:
    def test_defaults_to_invalid_request(self, app, client):
        mine = _authorize(client)
        with app.test_request_context("/"):
            response = views.authentication_error_redirect(mine["token"], None, None)
        assert response.status_code == 302
        assert parse_qs(urlsplit(response.headers["Location"]).query) == {
            "error": ["invalid_request"],
            "error_description": ["invalid_request"],
            "state": ["st"],  # the authorization request's state (RFC 6749 4.1.2.1)
        }
