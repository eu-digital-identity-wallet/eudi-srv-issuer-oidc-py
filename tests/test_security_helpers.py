"""Unit tests of the helpers in security.py: redirect URI policy, one-time
use, client authentication setup, rate limits and log redaction."""

import json
from types import SimpleNamespace

import pytest
from cryptojwt.jwt import JWT
from idpyoidc.message.oauth2 import ResponseMessage

import security
from security import OneTimeUse, configure_client_authentication, init_rate_limits, redact, trust_proxies, valid_redirect_uri
from conftest import FE, PREFIX


class TestValidRedirectUri:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://wallet.test/cb",
            "https://wallet.test/cb?x=1",
            "http://localhost:8080/cb",
            "http://127.0.0.1/cb",
            "http://[::1]:5000/cb",
            "eu.europa.ec.euidi://authorization",
            "asitplus-wallet://wallet.a-sit.plus/app/callback/provisioning",
            "myapp://cb",  # private-use scheme not in reverse-domain form
            "HTTPS://wallet.test/cb",
        ],
    )
    def test_accepted(self, uri):
        assert valid_redirect_uri(uri) is True

    @pytest.mark.parametrize(
        "uri",
        [
            None,
            "",
            42,
            " https://wallet.test/cb",  # surrounding whitespace
            "https://wallet.test/c b",  # control / space characters
            "https://wallet.test/\tcb",
            "https://wallet.test\\@evil.test/cb",  # backslash
            "https://[::1/cb",  # unparsable (ValueError)
            "https:///cb",  # no host
            "https://user:pw@wallet.test/cb",  # credentials
            "https://user@wallet.test/cb",
            "http://wallet.test/cb",  # http off loopback
            "http:///cb",  # http without host
            "http://10.0.0.1/cb",
            "http://user@127.0.0.1/cb",
            "data:text/html,x",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "VBScript:x",
            "blob:https://wallet.test/x",
            "about:blank",
            "/relative/cb",
            "https://wallet.test/cb#frag",
            "https://wallet.test/cb#",  # empty fragment
        ],
    )
    def test_refused(self, uri):
        assert valid_redirect_uri(uri) is False


class TestOneTimeUse:
    def test_second_use_refused_until_expiry(self, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(security, "time", SimpleNamespace(time=lambda: now[0]))
        once = OneTimeUse()
        assert once.first_use("v", 10) is True
        assert once.first_use("v", 10) is False
        now[0] += 11
        assert once.first_use("v", 10) is True

    def test_values_are_stored_hashed(self):
        once = OneTimeUse()
        once.first_use("secret-token", 10)
        assert "secret-token" not in once._seen

    def test_full_store_purges_expired_entries(self, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(security, "time", SimpleNamespace(time=lambda: now[0]))
        once = OneTimeUse(max_entries=2)
        once.first_use("a", 5)
        once.first_use("b", 5)
        now[0] += 6
        assert once.first_use("c", 5) is True
        assert len(once._seen) == 1

    def test_purge_expired_keeps_live_entries(self, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(security, "time", SimpleNamespace(time=lambda: now[0]))
        once = OneTimeUse()
        once.first_use("a", 5)
        once.first_use("b", 60)
        now[0] += 6
        assert once.purge_expired() == 1
        assert once.first_use("b", 60) is False
        assert once.first_use("a", 5) is True

    def test_full_store_of_live_entries_fails_closed(self):
        once = OneTimeUse(max_entries=2)
        assert once.first_use("a", 60) and once.first_use("b", 60)
        assert once.first_use("c", 60) is False


class TestClientAuthentication:
    def test_skips_missing_endpoints(self):
        token = SimpleNamespace(client_authn_method=None)
        endpoints = {"token": token}
        app = SimpleNamespace(server=SimpleNamespace(get_endpoint=endpoints.get))
        configure_client_authentication(app, require_wallet_attestation=False)
        assert token.client_authn_method == ["wallet_attestation", "public", "none"]

    def test_each_endpoint_gets_its_own_list(self, app):
        configure_client_authentication(app)
        token = app.server.get_endpoint("token").client_authn_method
        par = app.server.get_endpoint("pushed_authorization").client_authn_method
        assert token == par == ["wallet_attestation"] and token is not par


class TestSessionToken:
    def test_optional_claims(self, app):
        with app.test_request_context("/"):
            token = security.session_token("s1", scope="pid", authorization_details=[{"type": "x"}], frontend_id="fe")
            minimal = security.session_token("s2")
        context = app.server.get_context()
        unpack = JWT(context.keyjar, allowed_sign_algs=["ES256"]).unpack
        claims = unpack(token)
        assert claims["session_id"] == "s1" and claims["scope"] == "pid"
        assert claims["authorization_details"] == [{"type": "x"}] and claims["frontend_id"] == "fe"
        assert claims["iss"] == context.issuer
        bare = unpack(minimal)
        assert not {"scope", "authorization_details", "frontend_id"} & set(bare)


class TestRateLimitSettings:
    def test_disabled_returns_no_limiter(self, app):
        view = app.view_functions["oidc_op.token"]
        assert init_rate_limits(app, {"enabled": False}) is None
        assert app.view_functions["oidc_op.token"] is view

    def test_trusted_proxy_address_is_the_client(self, app):
        """Behind one trusted proxy, X-Forwarded-For names the client."""
        trust_proxies(app, 1)
        init_rate_limits(app, {"trusted_proxies": 1, "limits": {"oidc_op.token": "2 per minute"}})
        client = app.test_client()

        def codes(address, n):
            return [
                client.post(FE + "/token", data={"grant_type": "x"}, headers={"X-Forwarded-For": address}).status_code
                for _ in range(n)
            ]

        assert codes("198.51.100.1", 3) == [400, 400, 429]
        assert codes("198.51.100.2", 2) == [400, 400]

    def test_forwarder_without_a_wallet_hop_uses_its_own_address(self, app):
        init_rate_limits(app, {"forwarders": ["10.0.0.5"], "limits": {"oidc_op.token": "2 per minute"}})
        client = app.test_client()
        codes = [
            client.post(FE + "/token", data={"grant_type": "x"}, environ_base={"REMOTE_ADDR": "10.0.0.5"}).status_code
            for _ in range(3)
        ]
        assert codes == [400, 400, 429]

    def test_limits_for_unknown_views_are_ignored(self, app):
        assert init_rate_limits(app, {"limits": {"oidc_op.nonexistent": "1 per minute"}}) is not None
        assert "oidc_op.nonexistent" not in app.view_functions


class TestRedact:
    def test_message_object(self):
        message = ResponseMessage(error="x", access_token="secret")
        assert redact(message) == {"error": "x", "access_token": "<redacted>"}

    def test_object_whose_to_dict_fails(self):
        class Broken:
            def to_dict(self):
                raise RuntimeError("no")

        assert redact(Broken()) == "<unloggable>"

    def test_name_value_pair(self):
        assert redact({"name": "sid", "value": "secret", "path": "/"}) == {"name": "sid", "value": "<redacted>"}

    def test_lists_and_tuples(self):
        assert redact([{"code": "c"}, ("x", {"tx_code": 1})]) == [{"code": "<redacted>"}, ["x", {"tx_code": "<redacted>"}]]

    def test_case_insensitive_names(self):
        assert redact({"DPoP": "proof", "X-Api-Key": "k"}) == {"DPoP": "<redacted>", "X-Api-Key": "<redacted>"}

    def test_json_string(self):
        logged = redact('{"access_token": "secret", "token_type": "DPoP"}')
        assert json.loads(logged) == {"access_token": "<redacted>", "token_type": "DPoP"}

    def test_broken_json_string(self):
        assert redact('{"access_token": "secret"') == "<unloggable>"

    def test_url_with_secret_query(self):
        assert redact("https://w.test/cb?code=secret&state=s") == "https://w.test/cb?<redacted query>"

    def test_form_body_with_secret(self):
        assert redact("grant_type=x&refresh_token=secret") == "<redacted>"

    @pytest.mark.parametrize(
        "value",
        ["https://w.test/cb?state=s&x=1", "plain text", "a=b", 12, None],
    )
    def test_harmless_values_unchanged(self, value):
        assert redact(value) == value
