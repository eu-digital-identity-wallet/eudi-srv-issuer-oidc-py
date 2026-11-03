"""Regression tests for the 2026-07 security assessment findings."""

import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptojwt.jwt import JWT

from conftest import FE, FRONTEND_ID, PREFIX, BACKEND_API_KEY, make_wia_headers

import application

CLIENT_ID = "wallet-test"
REDIRECT_URI = "https://wallet.test/cb"
VERIFIER = "verifier-" + "x" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


def _authorize(client, **extra):
    """Runs a pushed authorization request (with a WIA), then the browser's
    authorization request; returns the backend redirect query."""
    issuer = f"{client.application.server.get_context().issuer}/{FRONTEND_ID}"
    args = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "eu.europa.ec.eudi.pid_mdoc",
        "state": "st",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        **extra,
    }
    pushed = client.post(
        FE + "/pushed_authorization", data=args, headers=make_wia_headers(issuer, CLIENT_ID)
    )
    assert pushed.status_code in (200, 201), pushed.data
    request_uri = json.loads(pushed.data)["request_uri"]
    response = client.get(
        FE + "/authorization", query_string={"client_id": CLIENT_ID, "request_uri": request_uri}
    )
    assert response.status_code == 302, response.data
    location = response.headers["Location"]
    assert location.startswith("https://backend.test/auth_choice?")
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


def _claims(app, token):
    context = app.server.get_context()
    return JWT(context.keyjar, allowed_sign_algs=["ES256"]).unpack(token)


class TestSessionHandOff:
    """AUTH-VULN-01 / AUTHZ-VULN-01: the backend trusted session_id from the query."""

    def test_redirect_carries_signed_session_token(self, app, client):
        query = _authorize(client)
        claims = _claims(app, query["session_token"])
        assert claims["session_id"] == query["session_id"]
        assert claims["scope"] == "eu.europa.ec.eudi.pid_mdoc"
        assert claims["aud"] == ["eudiw-issuer-backend"]
        assert claims["exp"] - claims["iat"] <= 300

    def test_session_token_cannot_be_forged(self, app, client):
        query = _authorize(client)
        header, payload, signature = query["session_token"].split(".")
        forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
        forged["session_id"] = "attacker-chosen"
        forged_payload = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
        with pytest.raises(Exception):
            _claims(app, f"{header}.{forged_payload}.{signature}")

    def test_issuer_state_never_becomes_the_session_id(self, client):
        query = _authorize(client, issuer_state="attacker-chosen")
        assert query["session_id"] != "attacker-chosen"
        stored = application.request_manager.get_request(session_id=query["session_id"])
        assert stored.issuer_state == "attacker-chosen"

    def test_par_issuer_state_never_becomes_the_session_id(self, client, wia):
        response = client.post(
            FE + "/pushed_authorization",
            data={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "eu.europa.ec.eudi.pid_mdoc",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "issuer_state": "victim-session",
            },
            headers=wia(),
        )
        assert response.status_code in (200, 201), response.data
        assert application.request_manager.get_request(session_id="victim-session") is None

    def test_verify_user_rejects_another_session(self, client):
        mine = _authorize(client)
        other = _authorize(client, state="other-state")
        response = client.get(
            PREFIX + "/verify/user", query_string={"token": mine["token"], "username": other["session_id"]}
        )
        assert response.status_code == 400
        assert b"Session mismatch" in response.data

    def test_verify_user_completes_its_own_session(self, client):
        mine = _authorize(client)
        response = client.get(
            PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]}
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(REDIRECT_URI)
        assert "code=" in response.headers["Location"]


class TestPreAuthorizedCodes:
    """Anyone could mint pre-authorized codes; the 5-digit tx_code had no attempt limit."""

    @pytest.fixture(autouse=True)
    def _wallet(self, wia):
        self.wia = wia

    def _generate(self, client, key=BACKEND_API_KEY):
        headers = {"X-Api-Key": key} if key else {}
        return client.post(PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers=headers)

    @pytest.mark.parametrize("key", [None, "wrong"])
    def test_preauth_generate_requires_the_backend_key(self, client, key):
        assert self._generate(client, key).status_code == 401

    def test_preauth_generate_fails_closed_without_configured_key(self, app, client):
        app.backend_api_key = "change-me"
        assert self._generate(client).status_code == 503

    def test_preauth_generate_with_key(self, client):
        body = self._generate(client).get_json()
        assert 10000 <= body["tx_code"] <= 99999 and body["preauth_code"] and body["session_id"]

    def _redeem(self, client, code, tx_code):
        return client.post(
            FE + "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": code,
                "tx_code": tx_code,
            },
            headers=_with_dpop(self.wia()),
        )

    def test_unknown_code_is_400_not_500(self, client):
        assert self._redeem(client, "unknown", "12345").status_code == 400

    def test_non_numeric_tx_code_is_400(self, client):
        body = self._generate(client).get_json()
        assert self._redeem(client, body["preauth_code"], "abcde").status_code == 400

    def test_code_revoked_after_five_wrong_tx_codes(self, client):
        body = self._generate(client).get_json()
        wrong = "00000" if body["tx_code"] != 0 else "11111"
        for _ in range(5):
            assert self._redeem(client, body["preauth_code"], wrong).status_code == 400
        response = self._redeem(client, body["preauth_code"], str(body["tx_code"]))
        assert response.status_code == 400
        assert "invalid or expired" in response.get_json()["error_description"]

    def test_code_is_single_use(self, client):
        body = self._generate(client).get_json()
        first = self._redeem(client, body["preauth_code"], str(body["tx_code"]))
        assert first.status_code == 200, first.data
        assert self._redeem(client, body["preauth_code"], str(body["tx_code"])).status_code == 400

    def test_code_expires(self, client):
        import datetime

        body = self._generate(client).get_json()
        stored = application.request_manager.get_request(session_id=body["session_id"])
        stored.preauth_expiry_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        assert self._redeem(client, body["preauth_code"], str(body["tx_code"])).status_code == 400

    def test_concurrent_guesses_cannot_exceed_the_limit(self, client):
        """A burst of guesses all found the code before any revoked it: 9 of 20 were compared."""
        import threading
        from collections import Counter

        body = self._generate(client).get_json()
        stored = application.request_manager.get_request(session_id=body["session_id"])
        wrong = "00000" if body["tx_code"] != 0 else "11111"
        barrier = threading.Barrier(20)
        outcomes = []

        def guess():
            barrier.wait()
            outcomes.append(application.request_manager.check_tx_code(stored, wrong))

        threads = [threading.Thread(target=guess) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert Counter(outcomes) == {"wrong": 4, "revoked": 1, "invalid": 15}
        assert application.request_manager.check_tx_code(stored, str(body["tx_code"])) == "invalid"


class TestRateLimits:
    def test_token_endpoint_throttled(self, app):
        from security import init_rate_limits

        init_rate_limits(app, {"limits": {"oidc_op.token": "3 per minute"}})
        client = app.test_client()
        codes = [client.post(FE + "/token", data={"grant_type": "x"}).status_code for _ in range(5)]
        assert codes[:3] == [400, 400, 400] and codes[3:] == [429, 429]

    @staticmethod
    def _token_codes(client, remote, forwarded):
        return [
            client.post(
                FE + "/token", data={"grant_type": "x"}, environ_base={"REMOTE_ADDR": remote},
                headers={"X-Forwarded-For": wallet},
            ).status_code
            for wallet in forwarded
        ]

    def test_wallets_behind_a_forwarder_have_their_own_limit(self, app):
        """Relayed requests (PAR through the frontend) shared the frontend's limit."""
        from security import init_rate_limits

        init_rate_limits(app, {"trusted_proxies": 0, "forwarders": ["10.0.0.5"],
                               "limits": {"oidc_op.token": "3 per minute"}})
        client = app.test_client()
        assert self._token_codes(client, "10.0.0.5", ["198.51.100.1"] * 4) == [400, 400, 400, 429]
        assert self._token_codes(client, "10.0.0.5", ["198.51.100.2"] * 3) == [400, 400, 400]

    def test_other_peers_cannot_choose_their_key(self, app):
        from security import init_rate_limits

        init_rate_limits(app, {"trusted_proxies": 0, "forwarders": ["10.0.0.5"],
                               "limits": {"oidc_op.token": "3 per minute"}})
        client = app.test_client()
        spoofed = [f"198.51.100.{i}" for i in range(10, 14)]
        assert self._token_codes(client, "10.0.0.9", spoofed) == [400, 400, 400, 429]


def _with_dpop(headers=None):
    """``headers`` plus a DPoP proof made with a new key (DPoP is required)."""
    from cryptography.hazmat.primitives.asymmetric import ec

    return {**(headers or {}), "DPoP": _dpop_proof(ec.generate_private_key(ec.SECP256R1()))}


def _dpop_proof(key, htu="https://issuer.eudiw.dev/oidc/fe/token", htm="POST", iat=None, alg="ES256", jti=None):
    import time
    import uuid

    import jwt as pyjwt

    public = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    return pyjwt.encode(
        {"jti": jti or str(uuid.uuid4()), "htm": htm, "htu": htu, "iat": int(iat or time.time())},
        key,
        algorithm=alg,
        headers={"typ": "dpop+jwt", "jwk": public},
    )


def _jkt(key):
    import jwt as pyjwt

    jwk = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


class TestDpopBinding:
    """AUTH-VULN-07: DPoP-bound tokens were accepted as plain bearer tokens."""

    @pytest.fixture(autouse=True)
    def _wallet(self, wia):
        self.wia = wia

    @pytest.fixture
    def key(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1())

    def _preauth_token(self, client, key, proof=None):
        body = client.post(
            PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        headers = {"DPoP": proof if proof is not None else _dpop_proof(key), **self.wia()}
        return client.post(
            FE + "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": body["preauth_code"],
                "tx_code": str(body["tx_code"]),
            },
            headers=headers,
        )

    def test_token_bound_and_introspection_reports_jkt(self, client, key):
        response = self._preauth_token(client, key)
        assert response.status_code == 200, response.data
        body = response.get_json()
        assert body["token_type"] == "DPoP"
        introspection = client.post(
            PREFIX + "/introspection", data={"token": body["access_token"]}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        assert introspection["active"] is True
        assert introspection["cnf"] == {"jkt": _jkt(key)}

    def test_introspection_requires_the_backend_key(self, client, key):
        token = self._preauth_token(client, key).get_json()["access_token"]
        assert client.post(PREFIX + "/introspection", data={"token": token}).status_code == 401

    @pytest.mark.parametrize(
        "variant",
        ["replayed", "old", "future", "wrong_method", "wrong_htu", "hmac"],
    )
    def test_invalid_proofs_rejected(self, client, key, variant):
        import time

        if variant == "replayed":
            proof = _dpop_proof(key, jti="fixed-jti")
            assert self._preauth_token(client, key, proof).status_code == 200
        elif variant == "old":
            proof = _dpop_proof(key, iat=time.time() - 3600)
        elif variant == "future":
            proof = _dpop_proof(key, iat=time.time() + 3600)
        elif variant == "wrong_method":
            proof = _dpop_proof(key, htm="GET")
        elif variant == "wrong_htu":
            proof = _dpop_proof(key, htu="https://attacker.test/token")
        else:
            import jwt as pyjwt

            proof = pyjwt.encode(
                {"jti": "j", "htm": "POST", "htu": "https://issuer.eudiw.dev/oidc/fe/token", "iat": int(time.time())},
                "secret-secret-secret-secret-secret",
                algorithm="HS256",
                headers={"typ": "dpop+jwt", "jwk": {"kty": "oct", "k": "c2VjcmV0"}},
            )
        response = self._preauth_token(client, key, proof)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"


class TestLogRedaction:
    """Codes, tokens and tx_codes were written to the logs."""

    def test_redact(self):
        from security import redact

        logged = str(
            redact(
                {
                    "headers": {"authorization": "DPoP secret-at", "dpop": "proof", "user-agent": "w"},
                    "cookie": [{"name": "sid", "value": "secret-cookie"}],
                    "form": {"code": "secret-code", "code_verifier": "secret-v", "grant_type": "authorization_code"},
                    "response": {"access_token": "secret-at2", "token_type": "DPoP", "tx_code": 12345},
                    "redirect": "https://wallet.test/cb?code=secret-code2&state=s",
                }
            )
        )
        for secret in ("secret-at", "proof", "secret-cookie", "secret-code", "secret-v", "secret-at2", "12345", "secret-code2"):
            assert secret not in logged
        assert "authorization_code" in logged and "'user-agent': 'w'" in logged

    def test_token_flow_logs_no_secrets(self, client, caplog, wia):
        import logging

        caplog.set_level(logging.DEBUG)
        body = client.post(
            PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        token = client.post(
            FE + "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": body["preauth_code"],
                "tx_code": str(body["tx_code"]),
            },
            headers=_with_dpop(wia()),
        ).get_json()
        text = caplog.text
        assert token["access_token"] not in text
        assert body["preauth_code"] not in text


class TestParErrors:
    def test_wia_for_another_client_is_a_client_error(self, client, monkeypatch):
        """A rejected client authentication at PAR is returned, not turned into a 500."""
        import views
        from flask import make_response

        monkeypatch.setattr(
            views, "service_endpoint",
            lambda endpoint, get_args=None, parse_kwargs=None: make_response(json.dumps({"error": "unauthorized_client"}), 401),
        )
        response = client.post(
            FE + "/pushed_authorization",
            data={"client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "response_type": "code"},
        )
        assert response.status_code == 401
        assert json.loads(response.data)["error"] == "unauthorized_client"

    def test_backend_only_endpoints_are_not_limited(self, app):
        """/preauth_generate and /introspection come from the backend's single address."""
        from security import init_rate_limits

        init_rate_limits(app, {"limits": {"oidc_op.token": "3 per minute"}})
        client = app.test_client()
        codes = {
            client.post(PREFIX + "/preauth_generate", data={"scope": "x", "frontend_id": FRONTEND_ID}, headers={"X-Api-Key": BACKEND_API_KEY}).status_code
            for _ in range(40)
        }
        assert 429 not in codes


class TestWalletAttestationRequired:
    """PAR and /token accepted any client_id without a Wallet Instance Attestation."""

    PAR = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "eu.europa.ec.eudi.pid_mdoc",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }

    def _par(self, client, headers=None, **extra):
        return client.post(FE + "/pushed_authorization", data={**self.PAR, **extra}, headers=headers or {})

    def _auth_code(self, client):
        mine = _authorize(client)
        location = client.get(
            PREFIX + "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]}
        ).headers["Location"]
        return parse_qs(urlsplit(location).query)["code"][0]

    def _code_token(self, client, code, headers=None):
        return client.post(
            FE + "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
            headers=_with_dpop(headers),
        )

    def test_par_with_wia(self, client, wia):
        assert self._par(client, wia()).status_code in (200, 201)

    def test_par_without_wia(self, client):
        response = self._par(client)
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_client"

    def test_par_forged_wia(self, client, wia):
        from cryptography.hazmat.primitives.asymmetric import ec

        assert self._par(client, wia(signer=ec.generate_private_key(ec.SECP256R1()))).status_code == 400

    def test_par_preauth_redirect_does_not_bypass_client_check(self, client, wia):
        # The server's own "preauth" placeholder is refused before client authentication.
        assert self._par(client, wia("another-wallet"), redirect_uri="preauth").status_code in (400, 401)

    def test_par_pop_for_another_server(self, client, wia):
        assert self._par(client, wia(pop_aud="https://other-as.test")).status_code == 400

    def test_par_pop_replayed(self, client, wia):
        headers = wia()
        assert self._par(client, headers).status_code in (200, 201)
        assert self._par(client, headers).status_code == 400

    def test_authorization_code_token_with_wia(self, client, wia):
        response = self._code_token(client, self._auth_code(client), wia())
        assert response.status_code == 200, response.data

    def test_authorization_code_token_without_wia(self, client):
        response = self._code_token(client, self._auth_code(client))
        assert response.status_code == 400

    def test_preauthorized_token_without_wia(self, client):
        body = client.post(
            PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        response = client.post(
            FE + "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": body["preauth_code"],
                "tx_code": str(body["tx_code"]),
            },
            headers=_with_dpop(),
        )
        assert response.status_code == 400


class TestPkceRequired:
    """PKCE was optional and allowed ``plain``: the add-on option was misspelt."""

    _par = TestWalletAttestationRequired._par
    PAR = TestWalletAttestationRequired.PAR

    def _without(self, *names):
        return {k: v for k, v in self.PAR.items() if k not in names}

    def test_par_without_code_challenge_is_rejected(self, client, wia):
        data = self._without("code_challenge", "code_challenge_method")
        response = client.post(FE + "/pushed_authorization", data=data, headers=wia())
        assert response.status_code == 400

    def test_par_with_plain_method_is_rejected(self, client, wia):
        response = self._par(client, wia(), code_challenge=VERIFIER, code_challenge_method="plain")
        assert response.status_code == 400

    def test_par_with_s256_is_accepted(self, client, wia):
        assert self._par(client, wia()).status_code in (200, 201)

    def test_only_s256_is_advertised(self, client):
        metadata = json.loads(client.get(FE + "/.well-known/openid-configuration").data)
        assert metadata.get("code_challenge_methods_supported") == ["S256"]


class TestUnusedEndpointsRemoved:
    """Open client registration (with remote jwks_uri fetches), userinfo and
    logout endpoints were exposed although no flow of this server uses them."""

    @pytest.mark.parametrize(
        "path",
        [
            PREFIX + "/registration",
            PREFIX + "/registration_api",
            PREFIX + "/userinfo",
            PREFIX + "/session",
            PREFIX + "/check_session_iframe",
            PREFIX + "/verify_logout",
            PREFIX + "/rp_logout",
            PREFIX + "/post_logout",
        ],
    )
    def test_not_routed(self, client, path):
        assert client.get(path).status_code == 404
        assert client.post(path).status_code in (404, 405)


class TestClientRegistration:
    """Any caller could register a client_id with any redirect_uri, before
    client authentication, overwriting the entry of a genuine wallet."""

    _par = TestWalletAttestationRequired._par
    PAR = TestWalletAttestationRequired.PAR

    @pytest.mark.parametrize(
        "uri",
        ["javascript:x", "//other.test/cb", "http://other.test/cb", "https://w.test/cb#f", "preauth", ""],
    )
    def test_unsafe_redirect_uri_is_refused(self, client, wia, uri):
        response = self._par(client, wia(), redirect_uri=uri)
        assert response.status_code == 400
        assert "Location" not in response.headers

    @pytest.mark.parametrize(
        "uri", ["https://wallet.test/cb", "http://127.0.0.1:5999/cb", "eu.europa.ec.euidi://authorization"]
    )
    def test_native_app_redirect_uris_are_accepted(self, client, wia, uri):
        assert self._par(client, wia(), redirect_uri=uri).status_code in (200, 201)

    def test_failed_client_authentication_leaves_the_client_unchanged(self, app, client, wia):
        assert self._par(client, wia()).status_code in (200, 201)
        cdb = app.server.get_context().cdb
        before = dict(cdb[CLIENT_ID])
        response = self._par(client, redirect_uri="https://other.test/cb")  # no WIA
        assert response.status_code == 400
        assert dict(cdb[CLIENT_ID]) == before

    def test_failed_client_authentication_registers_nothing(self, app, client):
        response = self._par(client, client_id="never-seen")
        assert response.status_code in (400, 401)
        assert "never-seen" not in app.server.get_context().cdb

    def test_non_pushed_authorization_request_is_refused(self, client):
        response = client.get(
            FE + "/authorization",
            query_string={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
            },
        )
        assert response.status_code == 400
        assert "Location" not in response.headers


class TestLogInjection:
    """Client-supplied values in log lines (SonarCloud log injection)."""

    def test_client_values_are_not_logged(self, app, client, wia, caplog):
        import logging

        with caplog.at_level(logging.DEBUG):
            TestWalletAttestationRequired()._par(client, wia(), redirect_uri="https://w.test/cb#\r\nFORGED-1")
            client.get(FE + "/authorization", query_string={"client_id": CLIENT_ID, "request_uri": "urn:x\r\nFORGED-2"})
            client.post(FE + "/token", data={"grant_type": "x\r\nFORGED-3"}, headers=_with_dpop())
        # Values may appear escaped inside a logged (redacted) payload, but a
        # line break from the client must never start a new log line.
        for record in caplog.records:
            message = record.getMessage()
            assert "\nFORGED" not in message and "\rFORGED" not in message


class TestConcurrentRegistration:
    """Concurrent registrations of one client (the internal pre-authorized
    client on every offer, a wallet running two flows) briefly left the client
    without redirect URIs: "No registered redirect_uri", answered with 500."""

    @staticmethod
    def _register(app, client_id, uri, internal=False):
        import views

        with app.test_request_context("/"):
            return views.dynamic_registration(client_id, uri, internal=internal)

    def test_known_redirect_uri_leaves_the_entry_untouched(self, app):
        cdb = app.server.get_context().cdb
        assert self._register(app, "eudiw-abca", "preauth", internal=True)[0] is None
        entry = cdb["eudiw-abca"]
        assert self._register(app, "eudiw-abca", "preauth", internal=True)[0] is None
        assert cdb["eudiw-abca"] is entry

    def test_concurrent_registrations_keep_every_uri_and_never_empty_the_client(self, app):
        import threading

        cdb = app.server.get_context().cdb
        assert self._register(app, "wallet-c", "https://wallet.test/cb0")[0] is None
        uris = [f"https://wallet.test/cb{i}" for i in range(1, 9)]
        barrier = threading.Barrier(len(uris) + 1)
        stop = threading.Event()
        seen_without_uris = []

        def reader():
            barrier.wait()
            while not stop.is_set():
                if not cdb.get("wallet-c", {}).get("redirect_uris"):
                    seen_without_uris.append(True)

        def register(uri):
            barrier.wait()
            assert self._register(app, "wallet-c", uri)[0] is None

        watcher = threading.Thread(target=reader)
        watcher.start()
        threads = [threading.Thread(target=register, args=(uri,)) for uri in uris]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stop.set()
        watcher.join()

        registered = {tuple(u)[0] for u in cdb["wallet-c"]["redirect_uris"]}
        assert registered == {"https://wallet.test/cb0", *uris}
        assert not seen_without_uris

    def test_restore_takes_back_only_its_own_uri(self, app):
        cdb = app.server.get_context().cdb
        assert self._register(app, "wallet-r", "https://wallet.test/a")[0] is None
        error, restore = self._register(app, "wallet-r", "https://wallet.test/b")
        assert error is None
        assert self._register(app, "wallet-r", "https://wallet.test/c")[0] is None
        restore()
        assert {tuple(u)[0] for u in cdb["wallet-r"]["redirect_uris"]} == {
            "https://wallet.test/a",
            "https://wallet.test/c",
        }

    def test_restore_removes_a_client_it_created(self, app):
        error, restore = self._register(app, "wallet-new", "https://wallet.test/cb")
        assert error is None
        restore()
        assert "wallet-new" not in app.server.get_context().cdb


class TestErrorRedirect:
    """Authorization errors redirected to any redirect_uri the request named."""

    def test_unregistered_uri_gets_json_not_a_redirect(self, app):
        import views

        with app.test_request_context("/"):
            response = views.auth_error_redirect(
                "https://other.test/cb", "server_error", "x", client_id=CLIENT_ID
            )
        assert response.status_code == 500
        assert "Location" not in response.headers
        assert json.loads(response.data)["error"] == "server_error"

    def test_without_client_gets_json(self, app):
        import views

        with app.test_request_context("/"):
            response = views.auth_error_redirect(REDIRECT_URI, "invalid_request")
        assert response.status_code == 400
        assert "Location" not in response.headers

    def test_registered_uri_gets_the_redirect(self, app, client, wia):
        import views

        assert TestWalletAttestationRequired()._par(client, wia()).status_code in (200, 201)
        with app.test_request_context("/"):
            response = views.auth_error_redirect(REDIRECT_URI, "access_denied", client_id=CLIENT_ID)
        assert response.status_code == 302
        assert response.headers["Location"].startswith(REDIRECT_URI + "?error=access_denied")


class TestAuthenticationHandOffToken:
    """The token returned through /verify/user never expired, could be
    redeemed for a new code again and again, and was accepted when signed by
    any key in the server's key jar."""

    def _verify(self, client, token, session_id):
        return client.get(PREFIX + "/verify/user", query_string={"token": token, "username": session_id})

    def test_token_is_single_use(self, client):
        mine = _authorize(client)
        assert self._verify(client, mine["token"], mine["session_id"]).status_code == 302
        again = self._verify(client, mine["token"], mine["session_id"])
        assert again.status_code == 400
        assert "Location" not in again.headers

    def test_token_expires(self, app, client):
        mine = _authorize(client)
        authn = app.server.get_context().authn_broker.get_method_by_id("user")
        claims = authn.unpack_token(mine["token"])
        assert "exp" in claims and claims["exp"] > claims["iat"]

    def test_token_from_another_issuer_is_refused(self, app):
        from idpyoidc.server.user_authn.user import create_signed_jwt

        context = app.server.get_context()
        authn = context.authn_broker.get_method_by_id("user")
        forged = create_signed_jwt(
            "https://other-issuer.test", context.keyjar, sign_alg=authn.sign_alg, lifetime=60, query="x"
        )
        with pytest.raises(Exception):
            authn.unpack_token(forged)

    def test_token_without_exp_is_refused(self, app):
        from idpyoidc.server.user_authn.user import create_signed_jwt

        context = app.server.get_context()
        authn = context.authn_broker.get_method_by_id("user")
        endless = create_signed_jwt(context.issuer, context.keyjar, sign_alg=authn.sign_alg, query="x")
        with pytest.raises(Exception):
            authn.unpack_token(endless)


class TestDpopRequired:
    """Tokens were issued as plain bearer tokens when no DPoP proof was sent."""

    def test_token_request_without_dpop_is_refused(self, client, wia):
        body = client.post(
            PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        response = client.post(
            FE + "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": body["preauth_code"],
                "tx_code": str(body["tx_code"]),
            },
            headers=wia(),
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"


class TestKeysRoute:
    def test_missing_file_is_404_not_500(self, client):
        assert client.get(PREFIX + "/keys/missing.json").status_code == 404

    def test_only_json_files_are_served(self, client):
        assert client.get(PREFIX + "/keys/config").status_code == 404


class TestOptionalProtocolFeatures:
    """OpenID4VCI 1.0 only RECOMMENDS PAR, PKCE, DPoP and wallet attestation:
    each is required by default and can be switched off for testing. A
    feature that is switched off but used anyway is still checked."""

    PAR = TestWalletAttestationRequired.PAR
    _par = TestWalletAttestationRequired._par

    @pytest.fixture
    def relaxed(self, app):
        from security import configure_client_authentication

        app.require_pushed_authorization_requests = False
        app.require_dpop = False
        configure_client_authentication(app, require_wallet_attestation=False)
        app.server.get_context().add_on["pkce"]["essential"] = False
        return app

    def _discovery(self, client):
        return json.loads(client.get(FE + "/.well-known/openid-configuration").data)

    def test_discovery_is_strict_by_default(self, client):
        doc = self._discovery(client)
        assert doc["require_pushed_authorization_requests"] is True
        assert doc["code_challenge_methods_supported"] == ["S256"]
        assert doc["token_endpoint_auth_methods_supported"] == ["attest_jwt_client_auth"]

    def test_discovery_follows_the_switches(self, relaxed, client):
        doc = self._discovery(client)
        assert doc["require_pushed_authorization_requests"] is False
        assert "none" in doc["token_endpoint_auth_methods_supported"]

    def test_plain_authorization_request_without_pkce(self, relaxed, client):
        response = client.get(
            FE + "/authorization",
            query_string={"client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "response_type": "code",
                          "scope": "eu.europa.ec.eudi.pid_mdoc", "state": "st"},
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith("https://backend.test/auth_choice?")

    def test_plain_authorization_request_still_checks_the_redirect_uri(self, relaxed, client):
        response = client.get(
            FE + "/authorization",
            query_string={"client_id": CLIENT_ID, "redirect_uri": "javascript:x", "response_type": "code"},
        )
        assert response.status_code == 400

    def test_par_without_wallet_attestation(self, relaxed, client):
        assert self._par(client).status_code in (200, 201)

    def test_a_wallet_attestation_that_is_sent_is_still_verified(self, relaxed, client, wia):
        from cryptography.hazmat.primitives.asymmetric import ec

        forged = wia(signer=ec.generate_private_key(ec.SECP256R1()))
        assert self._par(client, forged).status_code == 400

    def test_pkce_plain_is_still_refused_when_pkce_is_optional(self, relaxed, client):
        response = self._par(client, code_challenge="x" * 43, code_challenge_method="plain")
        assert response.status_code == 400

    def test_bearer_token_without_dpop_or_wia(self, relaxed, client):
        body = client.post(
            PREFIX + "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": FRONTEND_ID}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        response = client.post(
            FE + "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": body["preauth_code"],
                "tx_code": str(body["tx_code"]),
            },
        )
        assert response.status_code == 200, response.data
        assert response.get_json()["token_type"].lower() == "bearer"


class TestConfigurationFormats:
    """config.json became the commented config.yaml; JSON deployments keep working."""

    def test_yaml_and_json_load_the_same_configuration(self, tmp_path):
        import os

        import yaml
        from idpyoidc.util import load_config_file

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        yaml_path = os.path.join(root, "config.yaml")
        json_path = tmp_path / "config.json"
        json_path.write_text(json.dumps(yaml.safe_load(open(yaml_path))))
        assert load_config_file(yaml_path) == load_config_file(str(json_path))

    def test_openid4vci_switches_are_on_in_the_example(self):
        import os

        import yaml

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config = yaml.safe_load(open(os.path.join(root, "config.yaml")))
        assert config["require_pushed_authorization_requests"] is True
        assert config["require_dpop"] is True
        assert config["require_wallet_attestation"] is True
        assert config["op"]["server_info"]["add_ons"]["pkce"]["kwargs"] == {
            "essential": True,
            "code_challenge_methods": ["S256"],
        }
