"""Error conformance of the authorization side: /pushed_authorization
(RFC 9126), /authorization (RFC 6749 section 4.1.2.1, RFC 9396 section 5,
OpenID4VCI 1.0 section 5), /introspection (RFC 7662), client registration
(not exposed) and the .well-known metadata."""

import json
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest

import application
import views
from test_error_conformance import assert_oauth_error
from test_security import CHALLENGE, CLIENT_ID, REDIRECT_URI, TestWalletAttestationRequired
from test_views import API_KEY, _code_tokens, key, relaxed  # noqa: F401 (fixtures)
from conftest import FE, PREFIX

PAR = TestWalletAttestationRequired.PAR


def _par(client, headers, drop=(), **extra):
    data = {k: v for k, v in {**PAR, **extra}.items() if k not in drop}
    return client.post(FE + "/pushed_authorization", data=data, headers=headers)


def _request_uri(client, wia, **extra):
    response = _par(client, wia(), **extra)
    assert response.status_code == 201, response.data
    return response.get_json()["request_uri"]


def _authorize(client, request_uri, client_id=CLIENT_ID):
    query = {"request_uri": request_uri}
    if client_id is not None:
        query["client_id"] = client_id
    return client.get(FE + "/authorization", query_string=query)


def _error_redirect(response):
    """The query of an error redirect to the wallet's registered redirect URI."""
    assert response.status_code == 302, response.data
    location = response.headers["Location"]
    assert location.startswith(REDIRECT_URI + "?"), location
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


class TestPushedAuthorizationRequest:
    """RFC 9126 section 2."""

    @pytest.mark.parametrize("method", ["get", "put", "delete"])
    def test_other_methods_are_405(self, client, method):
        # RFC 9126 section 2.3
        response = getattr(client, method)(FE + "/pushed_authorization")
        assert response.status_code == 405
        assert response.headers["Allow"] == "POST"

    def test_success_is_201(self, client, wia):
        # RFC 9126 section 2.2
        response = _par(client, wia())
        assert response.status_code == 201
        assert response.mimetype == "application/json"
        body = response.get_json()
        assert body["request_uri"] and isinstance(body["expires_in"], int) and body["expires_in"] > 0

    @pytest.mark.parametrize("missing", ["client_id", "redirect_uri", "response_type"])
    def test_missing_required_parameter(self, client, wia, missing):
        assert_oauth_error(_par(client, wia(), drop=(missing,)), "invalid_request")

    def test_request_uri_is_not_allowed(self, app, client, wia, monkeypatch):
        # RFC 9126 section 2.1: request_uri MUST NOT be pushed (and is never fetched).
        context = app.server.get_context()
        monkeypatch.setattr(context, "httpc", lambda *a, **k: pytest.fail("request_uri was fetched"))
        response = _par(client, wia(), request_uri="https://attacker.test/request.jwt")
        assert_oauth_error(response, "invalid_request")

    def test_unsafe_redirect_uri(self, client, wia):
        # RFC 9126 section 2.3: invalid_request when the redirect URI is refused.
        assert_oauth_error(_par(client, wia(), redirect_uri="http://evil.test/cb"), "invalid_request")

    def test_unsupported_response_type(self, client, wia):
        # RFC 6749 section 4.1.2.1 codes apply (RFC 9126 section 2.3).
        assert_oauth_error(_par(client, wia(), response_type="token"), "unsupported_response_type")

    def test_missing_code_challenge(self, client, wia):
        # RFC 7636 section 4.4.1: PKCE required by this server.
        response = _par(client, wia(), drop=("code_challenge", "code_challenge_method"))
        assert_oauth_error(response, "invalid_request")

    def test_unsupported_code_challenge_method(self, client, wia):
        # RFC 7636 section 4.4.1: a method the server does not support.
        response = _par(client, wia(), code_challenge="v" * 50, code_challenge_method="plain")
        assert_oauth_error(response, "invalid_request")

    def test_malformed_authorization_details(self, client, wia):
        assert_oauth_error(_par(client, wia(), authorization_details="{not json"), "invalid_request")

    @pytest.mark.parametrize(
        "details",
        [
            {"type": "openid_credential", "credential_configuration_id": "x"},  # not an array
            [],
            ["openid_credential"],
            [{"credential_configuration_id": "x"}],  # no type
            [{"type": "payment_initiation"}],  # unknown type
            [{"type": "openid_credential", "credential_configuration_id": "x"}, {"type": "other"}],
        ],
    )
    def test_invalid_authorization_details(self, client, wia, details):
        # RFC 9396 section 5; OpenID4VCI 1.0 section 5.1.1 (type openid_credential).
        response = _par(client, wia(), authorization_details=json.dumps(details))
        assert_oauth_error(response, "invalid_authorization_details")

    def test_valid_authorization_details(self, client, wia):
        details = [{"type": "openid_credential", "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc"}]
        assert _par(client, wia(), authorization_details=json.dumps(details)).status_code == 201

    @pytest.mark.parametrize("variant", ["missing", "forged", "pop_audience", "pop_replayed"])
    def test_client_authentication_failure(self, client, wia, variant):
        from cryptography.hazmat.primitives.asymmetric import ec

        if variant == "missing":
            headers = {}
        elif variant == "forged":
            headers = wia(signer=ec.generate_private_key(ec.SECP256R1()))
        elif variant == "pop_audience":
            headers = wia(pop_aud="https://other-as.test")
        else:
            headers = wia()
            assert _par(client, headers).status_code == 201
        assert_oauth_error(_par(client, headers), "invalid_client", 400)

    def test_server_error_is_json(self, client, wia, monkeypatch):
        def fail(**kwargs):
            raise RuntimeError("full")

        monkeypatch.setattr(application.request_manager, "add_request", fail)
        assert_oauth_error(_par(client, wia()), "server_error", 500)


class TestAuthorizationRequest:
    """RFC 9126 section 4 and RFC 6749 section 4.1.2.1: errors are redirected
    only to a redirect URI the pushed (authenticated) request registered."""

    def test_par_is_required(self, client):
        response = client.get(
            FE + "/authorization",
            query_string={"client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "response_type": "code"},
        )
        assert_oauth_error(response, "invalid_request")
        assert "Location" not in response.headers

    def test_empty_request_uri(self, client):
        response = _authorize(client, "")
        assert_oauth_error(response, "invalid_request")
        assert "Location" not in response.headers

    def test_unknown_request_uri(self, client):
        response = _authorize(client, "urn:uuid:" + str(uuid.uuid4()))
        assert_oauth_error(response, "invalid_request_uri")
        assert "Location" not in response.headers

    def test_request_uri_is_single_use(self, client, wia):
        # RFC 9126 section 4: one-time use; the client and its redirect URI
        # are known, so the error is redirected, with the state.
        request_uri = _request_uri(client, wia, state="st-1")
        assert _authorize(client, request_uri).status_code == 302
        query = _error_redirect(_authorize(client, request_uri))
        assert query["error"] in ("invalid_request", "invalid_request_uri")
        assert query["state"] == "st-1"

    def test_expired_request_uri(self, app, client, wia):
        # RFC 9126 section 4: "An expired request_uri MUST be rejected as invalid."
        app.server.get_endpoint("pushed_authorization").ttl = 1
        request_uri = _request_uri(client, wia, state="st-2")
        time.sleep(2.1)
        response = _authorize(client, request_uri)
        if response.status_code == 302:
            query = _error_redirect(response)
            assert query["error"] in ("invalid_request", "invalid_request_uri")
            assert query["state"] == "st-2"
        else:
            assert_oauth_error(response, "invalid_request_uri")

    @pytest.mark.parametrize("client_id", ["another-wallet", None])
    def test_client_id_must_match_the_pushed_request(self, client, wia, client_id):
        # RFC 9126 section 2.2: the request_uri is bound to the client that
        # pushed it; RFC 9101 section 5: client_id is required.
        response = _authorize(client, _request_uri(client, wia), client_id=client_id)
        assert_oauth_error(response, "invalid_request")
        assert "Location" not in response.headers

    def test_internal_error_redirect_carries_the_state(self, client, wia, monkeypatch):
        request_uri = _request_uri(client, wia, state="st-3")

        def fail(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(views, "service_endpoint", fail)
        query = _error_redirect(_authorize(client, request_uri))
        assert query == {"error": "server_error", "error_description": "unhandled_exception", "state": "st-3"}

    def test_issuer_state_is_opaque(self, client, wia):
        # OpenID4VCI 1.0 section 5.1.3: issuer_state is opaque to the AS; an
        # unknown value is no error here (the Credential Issuer checks it).
        assert _authorize(client, _request_uri(client, wia, issuer_state="unknown")).status_code == 302


class TestNonPushedAuthorizationRequest:
    """With PAR switched off: no redirect to a redirect URI that is not
    (yet) verified (RFC 6749 section 4.1.2.1)."""

    ARGS = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }

    @pytest.mark.parametrize("missing", ["client_id", "redirect_uri", "response_type"])
    def test_missing_parameter(self, relaxed, client, missing):
        args = {k: v for k, v in self.ARGS.items() if k != missing}
        response = client.get(FE + "/authorization", query_string=args)
        assert_oauth_error(response, "invalid_request")
        assert "Location" not in response.headers

    def test_unsafe_redirect_uri(self, relaxed, client):
        response = client.get(FE + "/authorization", query_string={**self.ARGS, "redirect_uri": "http://evil.test/cb"})
        assert_oauth_error(response, "invalid_request")
        assert "Location" not in response.headers


class TestIntrospection:
    """RFC 7662. The caller is the issuer backend, authenticated by an API
    key, not by OAuth client credentials: the 401 uses this server's own
    ``unauthorized`` code rather than RFC 6749's invalid_client."""

    def _introspect(self, client, token, headers=API_KEY):
        return client.post(PREFIX + "/introspection", data={"token": token} if token else {}, headers=headers)

    @pytest.mark.parametrize("method", ["get", "put", "delete"])
    def test_other_methods_are_405(self, client, method):
        # RFC 7662 section 2.1: POST.
        assert getattr(client, method)(PREFIX + "/introspection").status_code == 405

    @pytest.mark.parametrize("headers", [{}, {"X-Api-Key": "wrong"}])
    def test_caller_not_authenticated(self, client, headers):
        # RFC 7662 section 2.3: 401 when the caller is not authorized.
        assert_oauth_error(self._introspect(client, "x", headers), "unauthorized", 401)

    def test_missing_token(self, client):
        # RFC 7662 section 2.1: token is REQUIRED.
        assert_oauth_error(self._introspect(client, None), "invalid_request")

    def test_unknown_token_is_inactive(self, client):
        # RFC 7662 section 2.2: {"active": false}, nothing else.
        response = self._introspect(client, "garbage")
        assert response.status_code == 200
        assert response.mimetype == "application/json"
        assert response.get_json() == {"active": False}
        assert response.headers["Cache-Control"] == "no-store"

    def test_expired_token_is_inactive(self, client, wia, key, monkeypatch):
        tokens = _code_tokens(client, wia, key)
        monkeypatch.setattr("idpyoidc.server.token.jwt_token.is_expired", lambda *a, **k: True)
        response = self._introspect(client, tokens["access_token"])
        assert response.status_code == 200
        assert response.get_json() == {"active": False}

    def test_revoked_token_is_inactive(self, app, client, wia, key):
        tokens = _code_tokens(client, wia, key)
        _mngr = app.server.get_context().session_manager
        _info = _mngr.get_session_info_by_token(tokens["access_token"], handler_key="access_token", grant=True)
        _info["grant"].get_token(tokens["access_token"]).revoke()
        response = self._introspect(client, tokens["access_token"])
        assert response.status_code == 200
        assert response.get_json() == {"active": False}


class TestRegistrationAndMetadata:
    def test_dynamic_registration_is_not_exposed(self, client):
        # RFC 7591 does not apply: clients are registered by PAR with a WIA.
        assert client.get(PREFIX + "/registration").status_code == 404
        assert client.post(PREFIX + "/registration", json={"redirect_uris": [REDIRECT_URI]}).status_code in (404, 405)

    @pytest.mark.parametrize("service", ["openid-configuration", "oauth-authorization-server"])
    def test_metadata(self, client, service):
        response = client.get(f"{FE}/.well-known/{service}")
        assert response.status_code == 200
        assert response.mimetype == "application/json"
        metadata = response.get_json()
        # draft-ietf-oauth-attestation-based-client-auth section 6.3: no
        # challenge endpoint, so use_attestation_challenge is never returned.
        assert "challenge_endpoint" not in metadata

    @pytest.mark.parametrize("service", ["security.txt", "openid-federation", "unknown"])
    def test_unknown_well_known_is_404(self, client, service):
        # RFC 8615 / RFC 8414 section 3: an unknown well-known URI does not exist.
        assert client.get(f"{FE}/.well-known/{service}").status_code == 404
