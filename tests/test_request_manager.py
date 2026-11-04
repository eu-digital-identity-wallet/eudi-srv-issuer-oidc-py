"""The in-memory authorization request store: data model, indexes, expiry,
thread safety and bounds."""

import datetime
import threading
import time

import pytest

from request_manager import (
    MAX_TX_CODE_ATTEMPTS,
    PREAUTH_CODE_LIFETIME_MINUTES,
    Oid4vciSession,
    RequestLimitExceeded,
    RequestManager,
)


def _expire(manager, session_id):
    manager._requests[session_id].expiry_time = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=1)


def test_expired_lookup_releases_the_index_lock_before_removal(monkeypatch):
    """Holding an index lock while taking every lock (from _requests_lock)
    deadlocked against clean_expired_requests."""
    manager = RequestManager()
    manager.add_request("c", "https://w.test/cb", "code", session_id="s")
    manager.update_code("s", "the-code")
    _expire(manager, "s")

    held = {}
    original = manager._remove_request_from_all_managers

    def remove(request_obj):
        free = []

        def try_lock():
            acquired = manager._requests_by_code_lock.acquire(blocking=False)
            free.append(acquired)
            if acquired:
                manager._requests_by_code_lock.release()

        probe = threading.Thread(target=try_lock)
        probe.start()
        probe.join()
        held["index_lock_free"] = free[0]
        return original(request_obj)

    monkeypatch.setattr(manager, "_remove_request_from_all_managers", remove)
    assert manager.get_request_by_code("the-code") is None
    assert held["index_lock_free"] is True


def test_store_is_capped():
    manager = RequestManager(max_requests=3)
    for i in range(3):
        manager.add_request("c", "https://w.test/cb", "code", session_id=f"s{i}")
    with pytest.raises(RequestLimitExceeded):
        manager.add_request("c", "https://w.test/cb", "code", session_id="s3")


def test_expired_requests_make_room():
    manager = RequestManager(max_requests=2)
    manager.add_request("c", "https://w.test/cb", "code", session_id="old")
    manager.add_request("c", "https://w.test/cb", "code", session_id="new")
    _expire(manager, "old")
    manager.add_request("c", "https://w.test/cb", "code", session_id="newer")
    assert manager.get_request("old") is None
    assert manager.get_request("newer") is not None


def test_expired_requests_are_cleaned_without_an_authorization_request(monkeypatch):
    manager = RequestManager()
    manager.add_request("c", "https://w.test/cb", "code", session_id="old")
    _expire(manager, "old")
    # The last clean was one interval ago, whatever the host's uptime.
    manager._last_clean = time.monotonic() - manager.CLEAN_INTERVAL
    manager.add_request("c", "https://w.test/cb", "code", session_id="new")
    assert "old" not in manager._requests


def test_cleaning_does_not_depend_on_host_uptime(monkeypatch):
    """time.monotonic() counts from boot: a host up for less than CLEAN_INTERVAL never cleaned."""
    import request_manager

    monkeypatch.setattr(request_manager.time, "monotonic", lambda: 5.0)  # 5 s after boot
    manager = RequestManager()
    manager.add_request("c", "https://w.test/cb", "code", session_id="old")
    _expire(manager, "old")
    manager._last_clean = float("-inf")
    manager.add_request("c", "https://w.test/cb", "code", session_id="new")
    assert "old" not in manager._requests


# --- Session data model -------------------------------------------------------

EXPIRY = datetime.datetime(2030, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)


def _full_session():
    return Oid4vciSession(
        client_id="c",
        redirect_uri="https://w.test/cb",
        response_type="code",
        session_id="s",
        expiry_time=EXPIRY,
        scope="pid",
        code_challenge_method="S256",
        code_challenge="chal",
        authorization_details=[{"type": "openid_credential"}],
        request_uri="urn:r",
        state="st",
        code="secret-code",
        access_token="secret-at",
        refresh_token="secret-rt",
        pre_authorized_code="secret-pac",
        pre_authorized_code_ref="secret-ref",
        tx_code=12345,
        frontend_id="fe",
        issuer_state="is",
    )


class TestSessionSerialization:
    def test_to_dict_minimal_has_only_mandatory_fields(self):
        """Unset optional attributes are left out of the dict."""
        session = Oid4vciSession("c", "https://w.test/cb", "code", "s", EXPIRY)
        assert session.to_dict() == {
            "client_id": "c",
            "redirect_uri": "https://w.test/cb",
            "response_type": "code",
            "session_id": "s",
            "expiry_time": "2030-01-02T03:04:05+00:00",
        }

    def test_to_dict_full_includes_every_set_field(self):
        data = _full_session().to_dict()
        assert data["scope"] == "pid"
        assert data["code_challenge_method"] == "S256"
        assert data["code_challenge"] == "chal"
        assert data["authorization_details"] == [{"type": "openid_credential"}]
        assert data["request_uri"] == "urn:r"
        assert data["state"] == "st"
        assert data["code"] == "secret-code"
        assert data["access_token"] == "secret-at"
        assert data["refresh_token"] == "secret-rt"
        assert data["pre_authorized_code"] == "secret-pac"
        assert data["pre_authorized_code_ref"] == "secret-ref"
        assert data["tx_code"] == 12345
        assert data["frontend_id"] == "fe"

    def test_repr_hides_secrets(self):
        """Codes, tokens and the tx_code are shown only as <set>."""
        text = repr(_full_session())
        for secret in ("secret-code", "secret-at", "secret-rt", "secret-pac", "secret-ref", "12345"):
            assert secret not in text
        for name in ("code", "access_token", "refresh_token", "pre_authorized_code", "pre_authorized_code_ref", "tx_code"):
            assert f"{name}=<set>" in text
        assert "scope='pid'" in text and "state='st'" in text and "frontend_id='fe'" in text
        assert "request_uri='urn:r'" in text and "code_challenge='chal'" in text
        assert "code_challenge_method='S256'" in text and "authorization_details=" in text
        assert text.startswith("Oid4vciRequest(session_id='s', client_id='c'")
        assert text.endswith("expiry_time='2030-01-02T03:04:05+00:00')")

    def test_repr_minimal(self):
        text = repr(Oid4vciSession("c", "https://w.test/cb", "code", "s", EXPIRY))
        assert "<set>" not in text and "scope=" not in text


# --- RequestManager updates and lookups --------------------------------------


@pytest.fixture
def manager():
    m = RequestManager()
    m.add_request("c", "https://w.test/cb", "code", session_id="s")
    return m


class TestUpdatesAndLookups:
    def test_add_request_generates_a_session_id(self):
        manager = RequestManager()
        obj = manager.add_request("c", "https://w.test/cb", "code")
        assert obj.session_id and manager.get_request(obj.session_id) is obj

    def test_update_request_uri_replaces_the_index_entry(self, manager):
        manager.update_request_uri("s", "urn:1")
        manager.update_request_uri("s", "urn:2")
        assert manager.get_request_by_uri("urn:1") is None
        assert manager.get_request_by_uri("urn:2").session_id == "s"

    def test_update_code_replaces_the_index_entry(self, manager):
        manager.update_code("s", "c1")
        manager.update_code("s", "c2")
        assert manager.get_request_by_code("c1") is None
        assert manager.get_request_by_code("c2").code == "c2"

    def test_update_access_token(self, manager):
        manager.update_access_token("s", "at")
        assert manager.get_request("s").access_token == "at"

    def test_update_refresh_token_replaces_the_index_entry(self, manager):
        manager.update_refresh_token("s", "rt1")
        manager.update_refresh_token("s", "rt2")
        assert manager.get_request_by_refresh_token("rt1") is None
        assert manager.get_request_by_refresh_token("rt2").refresh_token == "rt2"

    def test_update_refresh_token_keeps_the_session_for_its_lifetime(self, manager):
        week = 7 * 24 * 3600
        manager.update_refresh_token("s", "rt", lifetime_seconds=week)
        remaining = manager.get_request("s").expiry_time - datetime.datetime.now(
            datetime.timezone.utc
        )
        assert remaining.total_seconds() > week - 60

    def test_update_refresh_token_never_shortens_the_session(self, manager):
        before = manager.get_request("s").expiry_time
        manager.update_refresh_token("s", "rt", lifetime_seconds=1)
        assert manager.get_request("s").expiry_time == before

    def test_update_pre_authorized_code_replaces_the_index_entry(self, manager):
        manager.update_pre_authorized_code("s", "p1")
        manager.update_pre_authorized_code("s", "p2")
        assert manager.get_request_by_preauth_code("p1") is None
        assert manager.get_request_by_preauth_code("p2").pre_authorized_code == "p2"

    def test_update_pre_authorized_code_ref_resets_window_and_failures(self, manager):
        obj = manager.get_request("s")
        obj.tx_code_failures = 3
        before = datetime.datetime.now(datetime.timezone.utc)
        manager.update_pre_authorized_code_ref("s", "r1")
        manager.update_pre_authorized_code_ref("s", "r2")
        assert manager.get_request_by_preauth_code_ref("r1") is None
        assert manager.get_request_by_preauth_code_ref("r2") is obj
        assert obj.tx_code_failures == 0
        window = obj.preauth_expiry_time - before
        assert datetime.timedelta(minutes=PREAUTH_CODE_LIFETIME_MINUTES - 1) < window
        assert window <= datetime.timedelta(minutes=PREAUTH_CODE_LIFETIME_MINUTES, seconds=5)
        assert manager.preauth_code_expired(obj) is False

    def test_preauth_code_without_window_never_expires(self, manager):
        assert manager.preauth_code_expired(manager.get_request("s")) is False

    def test_update_tx_code_and_frontend_id(self, manager):
        manager.update_tx_code("s", 54321)
        manager.update_frontend_id("s", "fe-1")
        obj = manager.get_request("s")
        assert obj.tx_code == 54321 and obj.frontend_id == "fe-1"

    @pytest.mark.parametrize(
        "method, value",
        [
            ("update_request_uri", "urn:x"),
            ("update_code", "code"),
            ("update_access_token", "at"),
            ("update_refresh_token", "rt"),
            ("update_pre_authorized_code", "pac"),
            ("update_pre_authorized_code_ref", "ref"),
            ("update_tx_code", 1),
            ("update_frontend_id", "fe"),
        ],
    )
    def test_update_of_unknown_session_changes_nothing(self, manager, caplog, method, value):
        """Updating a non-existent session logs a warning and indexes nothing."""
        import logging

        with caplog.at_level(logging.WARNING, logger="request_manager"):
            getattr(manager, method)("missing", value)
        assert "non-existent session_id" in caplog.text
        assert manager.get_active_requests_count() == 1
        for index in (
            manager._requests_by_uri,
            manager._requests_by_code,
            manager._requests_by_preauth_code,
            manager._requests_by_preauth_code_ref,
            manager._requests_by_refresh_token,
        ):
            assert value not in index

    @pytest.mark.parametrize(
        "lookup", ["get_request_by_uri", "get_request_by_code", "get_request_by_preauth_code",
                   "get_request_by_preauth_code_ref", "get_request_by_refresh_token"],
    )
    def test_unknown_keys_are_not_found(self, manager, lookup):
        assert getattr(manager, lookup)("unknown") is None

    def test_get_request_unknown(self, manager):
        assert manager.get_request("unknown") is None

    def test_expired_request_is_removed_from_every_index(self, manager):
        manager.update_request_uri("s", "urn:x")
        manager.update_code("s", "code")
        manager.update_refresh_token("s", "rt")
        manager.update_pre_authorized_code("s", "pac")
        manager.update_pre_authorized_code_ref("s", "ref")
        _expire(manager, "s")
        assert manager.get_request("s") is None
        assert manager.get_active_requests_count() == 0
        for index in (
            manager._requests_by_uri,
            manager._requests_by_code,
            manager._requests_by_preauth_code,
            manager._requests_by_preauth_code_ref,
            manager._requests_by_refresh_token,
        ):
            assert index == {}

    @pytest.mark.parametrize(
        "update, lookup",
        [
            ("update_request_uri", "get_request_by_uri"),
            ("update_refresh_token", "get_request_by_refresh_token"),
            ("update_pre_authorized_code", "get_request_by_preauth_code"),
            ("update_pre_authorized_code_ref", "get_request_by_preauth_code_ref"),
        ],
    )
    def test_expired_lookup_returns_nothing(self, manager, update, lookup):
        getattr(manager, update)("s", "key")
        _expire(manager, "s")
        assert getattr(manager, lookup)("key") is None
        assert manager.get_active_requests_count() == 0

    def test_clean_expired_requests_keeps_live_ones(self, manager):
        manager.add_request("c", "https://w.test/cb", "code", session_id="live")
        manager.update_code("s", "old-code")
        _expire(manager, "s")
        manager.clean_expired_requests()
        assert manager.get_active_requests_count() == 1
        assert manager.get_request("live") is not None
        assert manager.get_request_by_code("old-code") is None

    def test_clean_with_nothing_expired(self, manager):
        manager.clean_expired_requests()
        assert manager.get_active_requests_count() == 1

    def test_re_adding_a_session_id_at_the_cap_replaces_it(self):
        """The cap applies to new sessions only."""
        manager = RequestManager(max_requests=1)
        manager.add_request("c", "https://w.test/cb", "code", session_id="s")
        replaced = manager.add_request("c2", "https://w.test/cb", "code", session_id="s")
        assert manager.get_request("s") is replaced and replaced.client_id == "c2"


class TestTxCodeAndRevocation:
    def test_check_tx_code(self, manager):
        manager.update_tx_code("s", 11111)
        obj = manager.get_request("s")
        assert manager.check_tx_code(obj, "11111") == "ok"
        assert manager.check_tx_code(obj, "22222") == "wrong"
        assert obj.tx_code_failures == 1

    def test_limit_revokes_the_codes(self, manager):
        manager.update_tx_code("s", 11111)
        manager.update_pre_authorized_code("s", "pac")
        manager.update_pre_authorized_code_ref("s", "ref")
        obj = manager.get_request("s")
        results = [manager.check_tx_code(obj, "0") for _ in range(MAX_TX_CODE_ATTEMPTS + 1)]
        assert results == ["wrong"] * (MAX_TX_CODE_ATTEMPTS - 1) + ["revoked", "invalid"]
        assert manager.get_request_by_preauth_code("pac") is None
        assert manager.get_request_by_preauth_code_ref("ref") is None
        # The session itself remains.
        assert manager.get_request("s") is obj

    def test_revoke_without_codes_is_harmless(self, manager):
        manager.revoke_preauth_code(manager.get_request("s"))
        assert manager.get_request("s") is not None
