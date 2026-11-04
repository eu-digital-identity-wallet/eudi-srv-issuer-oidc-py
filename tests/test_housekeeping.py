"""The background thread that removes expired entries from memory."""

import datetime
import time

import pytest
from idpyoidc.time_util import utc_time_sans_frac

import application
import housekeeping
import security


@pytest.fixture(autouse=True)
def _stopped():
    yield
    housekeeping.stop(timeout=5)


@pytest.fixture
def tokens(monkeypatch):
    once = security.OneTimeUse()
    monkeypatch.setattr(housekeeping, "used_authn_tokens", once)
    return once


def _expired_request(session_id):
    manager = application.request_manager
    manager.add_request("c", "https://w.test/cb", "code", session_id=session_id)
    manager._requests[session_id].expiry_time = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=1)


def _pushed_request(app, request_uri, expires_at):
    app.server.get_context().par_db[request_uri] = {"client_id": "c"}
    app.server.get_endpoint("pushed_authorization")._expires_at[request_uri] = expires_at


def test_run_once_removes_every_kind_of_expired_entry(app, tokens):
    _expired_request("old")
    tokens._seen["used"] = time.time() - 1
    _pushed_request(app, "urn:uuid:old", utc_time_sans_frac() - 1)
    _pushed_request(app, "urn:uuid:live", utc_time_sans_frac() + 60)

    housekeeping.run_once(app)

    assert "old" not in application.request_manager._requests
    assert tokens._seen == {}
    assert set(app.server.get_context().par_db) == {"urn:uuid:live"}


def test_a_failing_task_does_not_stop_the_others(app, tokens, monkeypatch, caplog):
    def boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(application.request_manager, "clean_expired_requests", boom)
    tokens._seen["used"] = time.time() - 1
    _pushed_request(app, "urn:uuid:old", utc_time_sans_frac() - 1)

    housekeeping.run_once(app)

    assert tokens._seen == {}
    assert "urn:uuid:old" not in app.server.get_context().par_db
    assert "Cleaning up expired authorization requests failed" in caplog.text


def test_pushed_requests_are_skipped_without_purge_support(app, monkeypatch):
    monkeypatch.setattr(app.server, "get_endpoint", lambda name: object())
    housekeeping._purge_pushed_requests(app)


def test_start_runs_periodically_and_is_idempotent(app, monkeypatch):
    runs = []
    monkeypatch.setattr(housekeeping, "run_once", runs.append)

    thread = housekeeping.start(app, interval_minutes=0.01 / 60)  # 10 ms
    assert housekeeping.start(app) is thread
    deadline = time.time() + 5
    while len(runs) < 2 and time.time() < deadline:
        time.sleep(0.01)

    assert runs[:2] == [app, app]
    assert thread.daemon


def test_stop_ends_the_thread(app):
    thread = housekeeping.start(app)
    housekeeping.stop(timeout=5)
    assert not thread.is_alive()
