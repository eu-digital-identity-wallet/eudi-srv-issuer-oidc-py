"""Background thread that removes expired entries from the in-memory stores.

Requests stay safe without it (lookups refuse expired entries), but entries
nobody looks up again would otherwise stay in memory.
"""

import logging
import threading
from typing import Optional

from application import request_manager
from security import used_authn_tokens

logger = logging.getLogger(__name__)

#: Minutes between two runs when ``cleanup_interval`` is not configured.
DEFAULT_CLEANUP_INTERVAL = 60

_thread: Optional[threading.Thread] = None
_stop = threading.Event()


def _purge_pushed_requests(app) -> None:
    endpoint = app.server.get_endpoint("pushed_authorization")
    # Older idpyoidc versions cannot purge pushed requests.
    purge = getattr(endpoint, "purge_expired", None)
    if purge:
        removed = purge()
        if removed:
            logger.debug(f"Removed {removed} expired pushed authorization requests.")


def run_once(app) -> None:
    """Runs every clean-up task; one failing does not stop the others."""
    tasks = (
        ("authorization requests", request_manager.clean_expired_requests),
        ("authentication tokens", used_authn_tokens.purge_expired),
        ("pushed authorization requests", lambda: _purge_pushed_requests(app)),
    )
    for name, task in tasks:
        try:
            task()
        except Exception:
            logger.exception(f"Cleaning up expired {name} failed")


def start(app, interval_minutes: float = DEFAULT_CLEANUP_INTERVAL) -> threading.Thread:
    """Starts the clean-up thread; later calls return the running one."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return _thread
    _stop.clear()

    def loop():
        while not _stop.wait(interval_minutes * 60):
            run_once(app)

    _thread = threading.Thread(target=loop, name="housekeeping", daemon=True)
    _thread.start()
    logger.info(f"Housekeeping started (expired entries removed every {interval_minutes} min).")
    return _thread


def stop(timeout: Optional[float] = None) -> None:
    """Stops the clean-up thread and waits for it to end."""
    global _thread
    _stop.set()
    if _thread is not None:
        _thread.join(timeout)
        _thread = None
