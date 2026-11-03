"""Error conformance of /token: the exact error code, HTTP status and
headers of every error path, including the ones answered by idpy-oidc.

RFC 6749 section 5.2 (token errors), RFC 7636 section 4.6 (PKCE),
OpenID4VCI 1.0 section 6.3 (pre-authorized code), RFC 9449 (DPoP) and
draft-ietf-oauth-attestation-based-client-auth (wallet attestation).
The authorization endpoints are in test_error_conformance_authz.py.
"""

import json
import time
import uuid
from unittest import mock

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from werkzeug.datastructures import Headers

import application
from test_security import CLIENT_ID, REDIRECT_URI, VERIFIER, _dpop_proof, _with_dpop
from test_views import API_KEY, PREAUTH_GRANT, _code, key  # noqa: F401 (fixture)
from conftest import FE, FRONTEND_ID, PREFIX

TOKEN_HTU = "https://issuer.eudiw.dev/oidc/fe/token"


def assert_oauth_error(response, error, status=400):
    """An RFC 6749 section 5.2 error: JSON with ``error`` (and, if present,
    ``error_description``, never a non-standard ``description``)."""
    assert response.status_code == status, response.data
    assert response.mimetype == "application/json"
    body = json.loads(response.data)
    assert body["error"] == error, body
    assert "description" not in body
    if "error_description" in body:
        assert isinstance(body["error_description"], str)
    return body


def assert_token_error(response, error, status=400):
    body = assert_oauth_error(response, error, status)
    # RFC 6749 section 5.1 asks for no-store on responses with tokens; this
    # server sends it on every /token response.
    assert response.headers.get("Cache-Control") == "no-store"
    return body


def _new_key():
    return ec.generate_private_key(ec.SECP256R1())


def _fresh_code(client):
    """An authorization code; each one from its own authorization request."""
    return _code(client, state=uuid.uuid4().hex)


def _code_request(code, **overrides):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": VERIFIER,
    }
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}


def _preauth_code(client):
    return client.post(
        PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers=API_KEY
    ).get_json()


def _redeem(client, headers, code, tx_code):
    data = {"grant_type": PREAUTH_GRANT}
    if code is not None:
        data["pre-authorized_code"] = code
    if tx_code is not None:
        data["tx_code"] = tx_code
    return client.post(FE + "/token", data=data, headers=headers)


def _expired_wia(wia):
    """A wallet attestation issued two hours ago (it expires after one)."""
    real = time.time
    with mock.patch("time.time", lambda: real() - 7200):
        return wia()


class TestTokenEndpoint:
    @pytest.mark.parametrize("method", ["get", "put", "delete"])
    def test_other_methods_are_405(self, client, method):
        # RFC 6749 section 3.2: the client MUST use POST.
        response = getattr(client, method)(FE + "/token")
        assert response.status_code == 405
        assert response.headers["Allow"] == "POST"
        assert response.mimetype == "application/json"

    def test_missing_dpop_proof(self, client, wia):
        # RFC 9449 section 5 / HAIP: DPoP is required at this server.
        response = client.post(FE + "/token", data=_code_request("x"), headers=wia())
        assert_token_error(response, "invalid_dpop_proof")

    def test_missing_grant_type(self, client):
        # RFC 6749 section 5.2: a missing required parameter is invalid_request.
        assert_token_error(client.post(FE + "/token", data={}, headers=_with_dpop()), "invalid_request")

    @pytest.mark.parametrize("grant_type", ["password", "client_credentials", "urn:x:unknown"])
    def test_unsupported_grant_type(self, client, grant_type):
        response = client.post(FE + "/token", data={"grant_type": grant_type}, headers=_with_dpop())
        assert_token_error(response, "unsupported_grant_type")

    def test_successful_response_is_not_cached(self, client, wia, key):
        # RFC 6749 section 5.1: Cache-Control: no-store and Pragma: no-cache.
        response = client.post(
            FE + "/token", data=_code_request(_fresh_code(client)), headers={**wia(), "DPoP": _dpop_proof(key)}
        )
        assert response.status_code == 200, response.data
        assert response.mimetype == "application/json"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Pragma"] == "no-cache"


class TestClientAuthentication:
    """invalid_client (RFC 6749 section 5.2) for wallet attestation failures.

    draft-ietf-oauth-attestation-based-client-auth section 7.4:
    invalid_client_attestation MAY be used, invalid_client is always fine.
    use_attestation_challenge / use_fresh_attestation do not apply: this
    server neither issues challenges nor has a freshness policy beyond exp.
    """

    def _token(self, client, headers, key, **overrides):
        return client.post(
            FE + "/token",
            data=_code_request(_fresh_code(client), **overrides),
            headers={**headers, "DPoP": _dpop_proof(key)},
        )

    def test_without_attestation(self, client, key):
        assert_token_error(self._token(client, {}, key), "invalid_client", 400)

    def test_forged_attestation(self, client, wia, key):
        assert_token_error(self._token(client, wia(signer=_new_key()), key), "invalid_client", 400)

    def test_expired_attestation(self, client, wia, key):
        assert_token_error(self._token(client, _expired_wia(wia), key), "invalid_client", 400)

    def test_pop_for_another_server(self, client, wia, key):
        assert_token_error(self._token(client, wia(pop_aud="https://other-as.test"), key), "invalid_client", 400)

    def test_attestation_for_another_client_id(self, client, wia, key):
        response = self._token(client, wia(), key, client_id="someone-else")
        assert_token_error(response, "invalid_client", 400)

    def test_attestation_failure_is_400(self, client, key):
        # RFC 6749 section 5.2: 401 (with WWW-Authenticate) is only required when
        # the client used the Authorization header; a wallet attestation does not.
        response = self._token(client, {}, key)
        assert response.status_code == 400
        assert "WWW-Authenticate" not in response.headers


class TestAuthorizationCodeGrant:
    def _post(self, client, wia, key, data):
        return client.post(FE + "/token", data=data, headers={**wia(), "DPoP": _dpop_proof(key)})

    def test_missing_code(self, client, wia, key):
        data = _code_request(None)
        assert_token_error(self._post(client, wia, key, data), "invalid_request")

    def test_unknown_code(self, client, wia, key):
        assert_token_error(self._post(client, wia, key, _code_request("unknown")), "invalid_grant")

    def test_code_used_twice(self, client, wia, key):
        data = _code_request(_fresh_code(client))
        assert self._post(client, wia, key, data).status_code == 200
        assert_token_error(self._post(client, wia, key, data), "invalid_grant")

    def test_code_issued_to_another_client(self, client, wia, key):
        data = _code_request(_fresh_code(client), client_id="another-wallet")
        response = client.post(FE + "/token", data=data, headers={**wia("another-wallet"), "DPoP": _dpop_proof(key)})
        assert_token_error(response, "invalid_grant")

    def test_redirect_uri_mismatch(self, client, wia, key):
        # RFC 6749 section 5.2: "does not match the redirection URI used in
        # the authorization request" is invalid_grant.
        data = _code_request(_fresh_code(client), redirect_uri="https://wallet.test/other")
        assert_token_error(self._post(client, wia, key, data), "invalid_grant")

    def test_pkce_wrong_verifier(self, client, wia, key):
        # RFC 7636 section 4.6
        data = _code_request(_fresh_code(client), code_verifier="w" * 60)
        assert_token_error(self._post(client, wia, key, data), "invalid_grant")

    def test_pkce_missing_verifier(self, client, wia, key):
        # RFC 7636 section 4.6 / RFC 9700 section 2.1.1: the code was bound
        # to a challenge, so it cannot be redeemed without the verifier.
        data = _code_request(_fresh_code(client), code_verifier=None)
        assert_token_error(self._post(client, wia, key, data), "invalid_grant")


class TestPreAuthorizedCodeGrant:
    """OpenID4VCI 1.0 section 6.3.

    "tx_code sent but not expected" (invalid_request) cannot happen here:
    /preauth_generate always issues a tx_code.
    """

    def test_missing_pre_authorized_code(self, client, wia):
        assert_token_error(_redeem(client, _with_dpop(wia()), None, "12345"), "invalid_request")

    def test_expected_tx_code_missing(self, client, wia):
        code = _preauth_code(client)
        assert_token_error(_redeem(client, _with_dpop(wia()), code["preauth_code"], None), "invalid_request")

    def test_wrong_tx_code(self, client, wia):
        code = _preauth_code(client)
        wrong = "00000" if code["tx_code"] != 0 else "11111"
        assert_token_error(_redeem(client, _with_dpop(wia()), code["preauth_code"], wrong), "invalid_grant")

    def test_unknown_pre_authorized_code(self, client, wia):
        assert_token_error(_redeem(client, _with_dpop(wia()), "unknown", "12345"), "invalid_grant")

    def test_expired_pre_authorized_code(self, client, wia):
        import datetime

        code = _preauth_code(client)
        stored = application.request_manager.get_request(session_id=code["session_id"])
        stored.preauth_expiry_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        response = _redeem(client, _with_dpop(wia()), code["preauth_code"], str(code["tx_code"]))
        assert_token_error(response, "invalid_grant")

    def test_used_pre_authorized_code(self, client, wia):
        code = _preauth_code(client)
        assert _redeem(client, _with_dpop(wia()), code["preauth_code"], str(code["tx_code"])).status_code == 200
        response = _redeem(client, _with_dpop(wia()), code["preauth_code"], str(code["tx_code"]))
        assert_token_error(response, "invalid_grant")

    def test_revoked_after_too_many_tx_codes(self, client, wia):
        code = _preauth_code(client)
        wrong = "00000" if code["tx_code"] != 0 else "11111"
        for _ in range(5):
            _redeem(client, _with_dpop(wia()), code["preauth_code"], wrong)
        response = _redeem(client, _with_dpop(wia()), code["preauth_code"], str(code["tx_code"]))
        assert_token_error(response, "invalid_grant")

    def test_anonymous_access_not_supported(self, client):
        # No wallet attestation: this server does not support anonymous access.
        code = _preauth_code(client)
        response = _redeem(client, _with_dpop(), code["preauth_code"], str(code["tx_code"]))
        assert_token_error(response, "invalid_client", 400)

    def test_successful_response_is_not_cached(self, client, wia):
        code = _preauth_code(client)
        response = _redeem(client, _with_dpop(wia()), code["preauth_code"], str(code["tx_code"]))
        assert response.status_code == 200, response.data
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Pragma"] == "no-cache"


class TestRefreshTokenGrant:
    @pytest.fixture
    def tokens(self, client, wia, key):
        response = client.post(
            FE + "/token", data=_code_request(_fresh_code(client)), headers={**wia(), "DPoP": _dpop_proof(key)}
        )
        assert response.status_code == 200, response.data
        return response.get_json()

    def _refresh(self, client, headers, refresh_token, key, **extra):
        data = {"grant_type": "refresh_token", "client_id": CLIENT_ID, **extra}
        if refresh_token is not None:
            data["refresh_token"] = refresh_token
        return client.post(FE + "/token", data=data, headers={**headers, "DPoP": _dpop_proof(key)})

    def test_missing_refresh_token(self, client, wia, key):
        assert_token_error(self._refresh(client, wia(), None, key), "invalid_request")

    def test_unknown_refresh_token(self, client, wia, key):
        assert_token_error(self._refresh(client, wia(), "unknown", key), "invalid_grant")

    def test_used_refresh_token(self, client, wia, key, tokens):
        assert self._refresh(client, wia(), tokens["refresh_token"], key).status_code == 200
        assert_token_error(self._refresh(client, wia(), tokens["refresh_token"], key), "invalid_grant")

    def test_expired_refresh_token(self, client, wia, key, tokens, monkeypatch):
        monkeypatch.setattr("idpyoidc.server.token.jwt_token.is_expired", lambda *a, **k: True)
        assert_token_error(self._refresh(client, wia(), tokens["refresh_token"], key), "invalid_grant")

    def test_revoked_refresh_token(self, app, client, wia, key, tokens):
        _mngr = app.server.get_context().session_manager
        _info = _mngr.get_session_info_by_token(tokens["refresh_token"], handler_key="refresh_token", grant=True)
        _info["grant"].get_token(tokens["refresh_token"]).revoke()
        assert_token_error(self._refresh(client, wia(), tokens["refresh_token"], key), "invalid_grant")

    def test_refresh_token_of_another_client(self, client, wia, key, tokens):
        response = self._refresh(
            client, wia("another-wallet"), tokens["refresh_token"], key, client_id="another-wallet"
        )
        assert_token_error(response, "invalid_grant")

    def test_broader_scope(self, client, wia, key, tokens):
        # RFC 6749 section 6: a scope not originally granted is invalid_scope.
        response = self._refresh(client, wia(), tokens["refresh_token"], key, scope="openid admin")
        assert_token_error(response, "invalid_scope")

    def test_another_dpop_key(self, client, wia, tokens):
        # RFC 9449 section 5: the refresh token is bound to the DPoP key.
        assert_token_error(self._refresh(client, wia(), tokens["refresh_token"], _new_key()), "invalid_dpop_proof")

    def test_without_attestation(self, client, key, tokens):
        assert_token_error(self._refresh(client, {}, tokens["refresh_token"], key), "invalid_client", 400)


class TestDpopProof:
    """RFC 9449 section 4.3 checks; each failure is invalid_dpop_proof (section 5).

    use_dpop_nonce (section 8) does not apply: this server provides no
    nonces, so a proof without one is accepted and no DPoP-Nonce is sent.
    """

    def _token(self, client, wia, dpop):
        code = _preauth_code(client)
        headers = Headers(wia())
        for proof in dpop if isinstance(dpop, list) else [dpop]:
            headers.add("DPoP", proof)
        return _redeem(client, headers, code["preauth_code"], str(code["tx_code"]))

    @staticmethod
    def _proof(key, header=None, claims=None, signer=None, alg="ES256"):
        public = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        payload = {"jti": str(uuid.uuid4()), "htm": "POST", "htu": TOKEN_HTU, "iat": int(time.time())}
        payload.update(claims or {})
        payload = {k: v for k, v in payload.items() if v is not None}
        headers = {"typ": "dpop+jwt", "jwk": public}
        headers.update(header or {})
        return pyjwt.encode(payload, signer or key, algorithm=alg, headers=headers)

    def test_without_nonce_is_accepted(self, client, wia, key):
        response = self._token(client, wia, _dpop_proof(key))
        assert response.status_code == 200, response.data
        assert "DPoP-Nonce" not in response.headers

    @pytest.mark.parametrize(
        "variant",
        [
            "not_a_jwt",
            "two_headers",
            "typ",
            "private_jwk",
            "no_jwk",
            "wrong_signature",
            "hmac",
            "no_jti",
            "htm",
            "htu",
            "old",
            "future",
            "replayed",
        ],
    )
    def test_invalid_proof(self, client, wia, key, variant):
        if variant == "not_a_jwt":
            dpop = "not-a-jwt"
        elif variant == "two_headers":
            dpop = [_dpop_proof(key), _dpop_proof(key)]
        elif variant == "typ":
            dpop = self._proof(key, header={"typ": "JWT"})
        elif variant == "private_jwk":
            dpop = self._proof(key, header={"jwk": json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key))})
        elif variant == "no_jwk":
            dpop = self._proof(key, header={"jwk": None})
        elif variant == "wrong_signature":
            dpop = self._proof(key, signer=_new_key())
        elif variant == "hmac":
            dpop = self._proof(key, header={"jwk": {"kty": "oct", "k": "c2VjcmV0"}}, signer="s" * 32, alg="HS256")
        elif variant == "no_jti":
            dpop = self._proof(key, claims={"jti": None})
        elif variant == "htm":
            dpop = self._proof(key, claims={"htm": "GET"})
        elif variant == "htu":
            dpop = self._proof(key, claims={"htu": "https://attacker.test/token"})
        elif variant == "old":
            dpop = self._proof(key, claims={"iat": int(time.time()) - 3600})
        elif variant == "future":
            dpop = self._proof(key, claims={"iat": int(time.time()) + 3600})
        else:
            dpop = _dpop_proof(key, jti="fixed-" + uuid.uuid4().hex)
            assert self._token(client, wia, dpop).status_code == 200
        assert_token_error(self._token(client, wia, dpop), "invalid_dpop_proof")
