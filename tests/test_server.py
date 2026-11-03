"""Start-up: server.create_app builds the app from the configuration and
server.main serves it with the webserver settings."""

import argparse
import json

import pytest
from flask import Flask

import server
from conftest import FE, PREFIX, BACKEND_API_KEY, _test_config


def _config(tmp_path, **overrides):
    """The test configuration with top-level ``overrides``; returns its path."""
    path = _test_config(tmp_path)
    with open(path) as f:
        config = json.load(f)
    config.update(overrides)
    with open(path, "w") as f:
        json.dump(config, f)
    return path


class TestCreateApp:
    def test_builds_the_configured_server(self, tmp_path):
        app, config = server.create_app(_config(tmp_path))
        assert app.backend_api_key == BACKEND_API_KEY
        assert app.authorization_redirect_url == "https://backend.test/auth_choice"
        assert app.require_pushed_authorization_requests is True
        assert app.require_dpop is True
        assert app.require_wallet_attestation is True
        assert app.server.get_endpoint("token").client_authn_method == ["wallet_attestation"]
        assert app.server.get_endpoint("pushed_authorization").client_authn_method == ["wallet_attestation"]
        assert config.web_conf["port"] == 5000

    def test_switches_off_only_when_false(self, tmp_path):
        app, _ = server.create_app(
            _config(
                tmp_path,
                require_pushed_authorization_requests=False,
                require_dpop=False,
                require_wallet_attestation=False,
            )
        )
        assert app.require_pushed_authorization_requests is False
        assert app.require_dpop is False
        assert app.require_wallet_attestation is False
        assert set(app.server.get_endpoint("token").client_authn_method) == {"wallet_attestation", "public", "none"}

    def test_missing_switches_default_to_required(self, tmp_path):
        path = _config(tmp_path)
        with open(path) as f:
            config = json.load(f)
        for name in ("require_pushed_authorization_requests", "require_dpop", "require_wallet_attestation"):
            config.pop(name, None)
        with open(path, "w") as f:
            json.dump(config, f)
        app, _ = server.create_app(path)
        assert app.require_pushed_authorization_requests and app.require_dpop and app.require_wallet_attestation

    def test_rate_limits_are_applied_when_enabled(self, tmp_path):
        app, _ = server.create_app(
            _config(tmp_path, rate_limiting={"limits": {"oidc_op.token": "2 per minute"}})
        )
        client = app.test_client()
        codes = [client.post(FE + "/token", data={"grant_type": "x"}).status_code for _ in range(3)]
        assert codes == [400, 400, 429]

    def test_serves_discovery(self, tmp_path):
        app, _ = server.create_app(_config(tmp_path))
        response = app.test_client().get(FE + "/.well-known/openid-configuration")
        assert response.status_code == 200
        assert response.get_json()["require_pushed_authorization_requests"] is True


class TestMain:
    @pytest.fixture
    def started(self, monkeypatch):
        """Records app.run and create_context instead of listening."""
        calls = {}
        monkeypatch.setattr(Flask, "run", lambda self, **kw: calls.setdefault("run", kw))
        monkeypatch.setattr(
            server, "create_context", lambda path, conf: calls.setdefault("context", (path, conf))
        )
        monkeypatch.setattr(
            server.housekeeping, "start", lambda app, interval: calls.setdefault("housekeeping", interval)
        )
        return calls

    def test_runs_with_the_webserver_settings(self, tmp_path, started):
        webserver = {"host": "127.0.0.1", "port": 5123, "debug": False, "domain": "x"}
        server.main(_config(tmp_path, webserver=webserver), argparse.Namespace(display=False))
        assert started["run"] == {"host": "127.0.0.1", "port": 5123, "debug": False}
        assert started["context"][0] == server.dir_path
        assert started["context"][1]["port"] == 5123
        assert started["housekeeping"] == server.housekeeping.DEFAULT_CLEANUP_INTERVAL

    def test_starts_housekeeping_with_the_configured_interval(self, tmp_path, started):
        server.main(_config(tmp_path, cleanup_interval=5), argparse.Namespace(display=False))
        assert started["housekeeping"] == 5

    def test_host_defaults_to_every_interface(self, tmp_path, started):
        server.main(_config(tmp_path, webserver={"port": 5001, "debug": True}), argparse.Namespace(display=False))
        assert started["run"] == {"host": "0.0.0.0", "port": 5001, "debug": True}

    def test_display_prints_provider_info_and_exits(self, tmp_path, started, capsys):
        with pytest.raises(SystemExit) as exc:
            server.main(_config(tmp_path), argparse.Namespace(display=True))
        assert exc.value.code == 0
        assert "run" not in started and "housekeeping" not in started
        info = json.loads(capsys.readouterr().out)
        assert info["issuer"] == "https://issuer.eudiw.dev/oidc"

    def test_display_never_starts_the_server(self, tmp_path, started):
        """Whatever -d does, it does not fall through to app.run."""
        with pytest.raises((SystemExit, AttributeError)):
            server.main(_config(tmp_path), argparse.Namespace(display=True))
        assert "run" not in started
