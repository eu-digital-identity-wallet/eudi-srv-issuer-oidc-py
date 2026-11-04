import secrets
import datetime
import logging
import threading
import time
import uuid
from typing import Union, Dict, Optional

logger = logging.getLogger(__name__)

#: Minutes a pre-authorized code can be redeemed after it was issued.
PREAUTH_CODE_LIFETIME_MINUTES = 10
#: Wrong tx_code attempts after which a pre-authorized code is revoked.
MAX_TX_CODE_ATTEMPTS = 5


# --- Oid4vciSession: The data model for a single request session ---
# This class is a simple data container. It holds the state for a single
# OID4VCI request lifecycle and does not perform any multi-threaded operations.
# Therefore, it does not need any locks.
class Oid4vciSession:
    """
    A class to represent an OID4VCI (OpenID for Verifiable Credential Issuance) request.
    It includes session management details, tokens, and other relevant parameters.

    Attributes:
        client_id (str): The client identifier.
        redirect_uri (str): The URI for post-authorization redirection.
        response_type (str): The response type, e.g., "code".
        scope (Optional[str]): A space-separated list of scopes.
        code_challenge_method (Optional[str]): The PKCE code challenge method.
        code_challenge (Optional[str]): The PKCE code challenge.
        authorization_details (Optional[Dict]): Authorization details from the request.
        session_id (str): A unique identifier for this request session.
        expiry_time (datetime.datetime): The UTC datetime when this session expires.
        request_uri (Optional[str]): The request_uri from a Pushed Authorization Request (PAR).
        state (Optional[str]): An opaque value used by the client.
        code (Optional[str]): The authorization code issued.
        access_token (Optional[str]): The access token issued.
        refresh_token (Optional[str]): The refresh token issued.
        pre_authorized_code (Optional[str]): The pre-authorized code for direct issuance.
        pre_authorized_code_ref (Optional[str]): The reference value for the pre-authorized code.
        tx_code (Optional[int]): The transaction code for the issuance process.
        frontend_id (Optional[str]): The frontend identifier associated with this session.
        issuer_state (Optional[str]): issuer_state sent by the wallet (from a
            credential offer); never used as the session id.
        tx_code_failures (int): Wrong tx_code attempts so far.
        preauth_expiry_time (Optional[datetime.datetime]): When the
            pre-authorized code stops being redeemable.
    """

    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        session_id: str,
        expiry_time: datetime.datetime,
        scope: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        code_challenge: Optional[str] = None,
        authorization_details: Optional[Dict] = None,
        request_uri: Optional[str] = None,
        state: Optional[str] = None,
        code: Optional[str] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        pre_authorized_code: Optional[str] = None,
        pre_authorized_code_ref: Optional[str] = None,
        tx_code: Optional[int] = None,
        frontend_id: Optional[str] = None,
        issuer_state: Optional[str] = None,
    ):
        """Initializes a new Oid4vciRequest instance."""
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.response_type = response_type
        self.scope = scope
        self.code_challenge_method = code_challenge_method
        self.code_challenge = code_challenge
        self.authorization_details = authorization_details
        self.session_id = session_id
        self.expiry_time = expiry_time
        self.request_uri = request_uri
        self.state = state
        self.code = code
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.pre_authorized_code = pre_authorized_code
        self.pre_authorized_code_ref = pre_authorized_code_ref
        self.tx_code = tx_code
        self.frontend_id = frontend_id
        self.issuer_state = issuer_state
        self.tx_code_failures = 0
        self.preauth_expiry_time: Optional[datetime.datetime] = None

    def to_dict(self) -> Dict:
        """Converts the Oid4vciRequest object into a dictionary."""
        data = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": self.response_type,
            "session_id": self.session_id,
            "expiry_time": self.expiry_time.isoformat(),
        }
        # Add optional attributes if they exist
        if self.scope is not None:
            data["scope"] = self.scope
        if self.code_challenge_method is not None:
            data["code_challenge_method"] = self.code_challenge_method
        if self.code_challenge is not None:
            data["code_challenge"] = self.code_challenge
        if self.authorization_details is not None:
            data["authorization_details"] = self.authorization_details
        if self.request_uri is not None:
            data["request_uri"] = self.request_uri
        if self.state is not None:
            data["state"] = self.state
        if self.code is not None:
            data["code"] = self.code
        if self.access_token is not None:
            data["access_token"] = self.access_token
        if self.refresh_token is not None:
            data["refresh_token"] = self.refresh_token
        if self.pre_authorized_code is not None:
            data["pre_authorized_code"] = self.pre_authorized_code
        if self.pre_authorized_code_ref is not None:
            data["pre_authorized_code_ref"] = self.pre_authorized_code_ref
        if self.tx_code is not None:
            data["tx_code"] = self.tx_code
        if self.frontend_id is not None:
            data["frontend_id"] = self.frontend_id
        return data

    def __repr__(self):
        """Returns a string representation of the Oid4vciRequest object."""
        optional_parts = []
        if self.scope:
            optional_parts.append(f"scope='{self.scope}'")
        if self.code_challenge_method:
            optional_parts.append(
                f"code_challenge_method='{self.code_challenge_method}'"
            )
        if self.code_challenge:
            optional_parts.append(f"code_challenge='{self.code_challenge}'")
        if self.authorization_details:
            optional_parts.append(f"authorization_details={self.authorization_details}")
        if self.request_uri:
            optional_parts.append(f"request_uri='{self.request_uri}'")
        if self.state:
            optional_parts.append(f"state='{self.state}'")
        # Codes, tokens and the tx_code are secrets: only their presence is shown.
        for name in ("code", "access_token", "refresh_token", "pre_authorized_code", "pre_authorized_code_ref", "tx_code"):
            if getattr(self, name):
                optional_parts.append(f"{name}=<set>")
        if self.frontend_id:
            optional_parts.append(f"frontend_id='{self.frontend_id}'")

        return (
            f"Oid4vciRequest(session_id='{self.session_id}', "
            f"client_id='{self.client_id}', "
            f"redirect_uri='{self.redirect_uri}', "
            f"response_type='{self.response_type}', "
            f"{', '.join(optional_parts)}, "
            f"expiry_time='{self.expiry_time.isoformat()}')"
        )


class RequestLimitExceeded(Exception):
    """Raised when the in-memory request store is full of live requests."""


# --- RequestManager: The thread-safe manager for all request sessions ---
# This class manages the state for multiple in-flight requests. Because it is
# accessed by different threads simultaneously (e.g., from a Flask web server),
# it must be thread-safe. This implementation achieves thread safety using
# fine-grained locking, with a separate lock for each dictionary.
class RequestManager:
    """
    Manages Oid4vciRequest objects with fine-grained locking.
    This ensures that multiple threads can safely read and write to different
    parts of the data store concurrently without corrupting data.
    """

    #: Seconds between two automatic clean-ups of expired requests.
    CLEAN_INTERVAL = 60

    def __init__(self, default_expiry_minutes: int = 15, max_requests: int = 50_000):
        # The primary storage for request objects, keyed by a unique session ID.
        self._requests: Dict[str, Oid4vciSession] = {}
        # Secondary indexes for fast lookup by different attributes.
        self._requests_by_uri: Dict[str, Oid4vciSession] = {}
        self._requests_by_code: Dict[str, Oid4vciSession] = {}
        self._requests_by_preauth_code: Dict[str, Oid4vciSession] = {}
        self._requests_by_preauth_code_ref: Dict[str, Oid4vciSession] = {}
        self._requests_by_refresh_token: Dict[str, Oid4vciSession] = {}

        self.default_expiry_minutes = default_expiry_minutes
        # Requests are kept in memory: cap them so a flood cannot exhaust it.
        self.max_requests = max_requests
        # Never cleaned yet: the first call is due. (0.0 was not: time.monotonic()
        # counts from boot, so on a host up for less than CLEAN_INTERVAL nothing
        # was cleaned.)
        self._last_clean = float("-inf")

        # Create a separate lock for each dictionary to enable fine-grained locking.
        # This allows a thread to access one dictionary while another thread
        # accesses a different one.
        self._requests_lock = threading.RLock()
        self._requests_by_uri_lock = threading.RLock()
        self._requests_by_code_lock = threading.RLock()
        self._requests_by_preauth_code_lock = threading.RLock()
        self._requests_by_preauth_code_ref_lock = threading.RLock()
        self._requests_by_refresh_token_lock = threading.RLock()

    def add_request(
        self,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        scope: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        code_challenge: Optional[str] = None,
        authorization_details: Optional[Dict] = None,
        session_id: Optional[str] = None,
        request_uri: Optional[str] = None,
        state: Optional[str] = None,
        pre_authorized_code: Optional[str] = None,
        pre_authorized_code_ref: Optional[str] = None,
        tx_code: Optional[int] = None,
        frontend_id: Optional[str] = None,
        issuer_state: Optional[str] = None,
    ) -> Oid4vciSession:
        """
        Creates and stores a new Oid4vciRequest object.
        Only needs to lock the primary requests dictionary, as it's the only one
        being modified by this method.
        """
        if session_id is None:
            session_id = str(uuid.uuid4())

        expiry_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=self.default_expiry_minutes
        )

        request_obj = Oid4vciSession(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            session_id=session_id,
            expiry_time=expiry_time,
            scope=scope,
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
            authorization_details=authorization_details,
            request_uri=request_uri,
            state=state,
            pre_authorized_code=pre_authorized_code,
            pre_authorized_code_ref=pre_authorized_code_ref,
            tx_code=tx_code,
            frontend_id=frontend_id,
            issuer_state=issuer_state,
        )

        self._clean_if_due()
        # Acquire lock only for the primary _requests dictionary.
        with self._requests_lock:
            if session_id not in self._requests and len(self._requests) >= self.max_requests:
                self.clean_expired_requests()
                if len(self._requests) >= self.max_requests:
                    raise RequestLimitExceeded("Too many pending authorization requests")
            self._requests[session_id] = request_obj
            logger.debug(
                f"Added request with session_id: {session_id} (Expires: {expiry_time.isoformat()})"
            )
        return request_obj

    def update_request_uri(self, session_id: str, request_uri: str):
        """
        Updates the 'request_uri' and the corresponding index.
        This operation requires locking both the primary and URI dictionaries
        to ensure atomicity and consistency.
        """
        with self._requests_lock, self._requests_by_uri_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                # Remove old URI mapping to prevent stale data
                if (
                    request_obj.request_uri
                    and request_obj.request_uri in self._requests_by_uri
                ):
                    del self._requests_by_uri[request_obj.request_uri]

                request_obj.request_uri = request_uri
                self._requests_by_uri[request_uri] = request_obj
                logger.debug(f"Updated request {session_id} with request_uri: {request_uri}")
            else:
                logger.warning(
                    f"Attempted to update URI for non-existent session_id: {session_id}"
                )

    def update_code(self, session_id: str, code: str):
        """
        Updates the 'code' and its lookup index.
        Requires locking both the primary and code dictionaries.
        """
        with self._requests_lock, self._requests_by_code_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                if request_obj.code and request_obj.code in self._requests_by_code:
                    del self._requests_by_code[request_obj.code]

                request_obj.code = code
                self._requests_by_code[code] = request_obj
                logger.debug(f"Updated code for session_id {session_id}")
            else:
                logger.warning(
                    f"Attempted to update code for non-existent session_id: {session_id}"
                )

    def update_access_token(self, session_id: str, access_token: str):
        """
        Updates the 'access_token'. Only the primary dictionary needs to be locked
        because no secondary index relies on this attribute.
        """
        with self._requests_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                request_obj.access_token = access_token
                logger.debug(
                    f"Updated access_token for session_id {session_id}"
                )
            else:
                logger.warning(
                    f"Attempted to update access_token for non-existent session_id: {session_id}"
                )

    def update_refresh_token(
        self, session_id: str, refresh_token: str, lifetime_seconds: Optional[int] = None
    ):
        """
        Updates the 'refresh_token' and its lookup index.
        Requires locking both the primary and refresh token dictionaries.

        :param lifetime_seconds: how long the refresh token is valid; the session
            is kept at least that long, or the token could not be looked up.
        """
        with self._requests_lock, self._requests_by_refresh_token_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                if (
                    request_obj.refresh_token
                    and request_obj.refresh_token in self._requests_by_refresh_token
                ):
                    del self._requests_by_refresh_token[request_obj.refresh_token]

                request_obj.refresh_token = refresh_token
                self._requests_by_refresh_token[refresh_token] = request_obj
                if lifetime_seconds:
                    request_obj.expiry_time = max(
                        request_obj.expiry_time,
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(seconds=lifetime_seconds),
                    )
                logger.debug(
                    f"Updated refresh_token for session_id {session_id}"
                )
            else:
                logger.warning(
                    f"Attempted to update refresh_token for non-existent session_id: {session_id}"
                )

    def update_pre_authorized_code(self, session_id: str, pre_authorized_code: str):
        """
        Updates the 'pre_authorized_code' and its lookup index.
        Requires locking both the primary and pre-authorized code dictionaries.
        """
        with self._requests_lock, self._requests_by_preauth_code_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                if (
                    request_obj.pre_authorized_code
                    and request_obj.pre_authorized_code
                    in self._requests_by_preauth_code
                ):
                    del self._requests_by_preauth_code[request_obj.pre_authorized_code]

                request_obj.pre_authorized_code = pre_authorized_code
                self._requests_by_preauth_code[pre_authorized_code] = request_obj
                logger.debug(
                    f"Updated pre_authorized_code for session_id {session_id}"
                )
            else:
                logger.warning(
                    f"Attempted to update pre_authorized_code for non-existent session_id: {session_id}"
                )

    def update_pre_authorized_code_ref(
        self, session_id: str, pre_authorized_code_ref: str
    ):
        """
        Updates the 'pre_authorized_code_ref' and its lookup index.
        Requires locking both the primary and pre-authorized code ref dictionaries.
        """
        with self._requests_lock, self._requests_by_preauth_code_ref_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                if (
                    request_obj.pre_authorized_code_ref
                    and request_obj.pre_authorized_code_ref
                    in self._requests_by_preauth_code_ref
                ):
                    del self._requests_by_preauth_code_ref[
                        request_obj.pre_authorized_code_ref
                    ]

                request_obj.pre_authorized_code_ref = pre_authorized_code_ref
                request_obj.preauth_expiry_time = datetime.datetime.now(
                    datetime.timezone.utc
                ) + datetime.timedelta(minutes=PREAUTH_CODE_LIFETIME_MINUTES)
                request_obj.tx_code_failures = 0
                self._requests_by_preauth_code_ref[pre_authorized_code_ref] = (
                    request_obj
                )
                logger.debug(
                    f"Updated pre_authorized_code_ref for session_id {session_id}"
                )
            else:
                logger.warning(
                    f"Attempted to update pre_authorized_code_ref for non-existent session_id: {session_id}"
                )

    def preauth_code_expired(self, request_obj: Oid4vciSession) -> bool:
        """Tells whether a pre-authorized code is past its redemption window."""
        expiry = request_obj.preauth_expiry_time
        return expiry is not None and datetime.datetime.now(datetime.timezone.utc) >= expiry

    def check_tx_code(self, request_obj: Oid4vciSession, candidate) -> str:
        """Compares a tx_code and counts a wrong one, in one step.

        Concurrent guesses all found the code before any revoked it, so more
        than ``MAX_TX_CODE_ATTEMPTS`` could be compared. The comparison and the
        count now happen under one lock, and a code that reached the limit is
        never compared again.

        Returns:
            ``"ok"``; ``"wrong"``; ``"revoked"`` (this guess reached the
            limit); or ``"invalid"`` (the limit was already reached).
        """
        with self._requests_lock:
            if request_obj.tx_code_failures >= MAX_TX_CODE_ATTEMPTS:
                return "invalid"
            if secrets.compare_digest(str(candidate), str(request_obj.tx_code)):
                return "ok"
            request_obj.tx_code_failures += 1
            revoked = request_obj.tx_code_failures >= MAX_TX_CODE_ATTEMPTS
        if revoked:
            logger.warning(f"Too many wrong tx_code attempts for session_id {request_obj.session_id}; code revoked")
            self.revoke_preauth_code(request_obj)
        return "revoked" if revoked else "wrong"

    def revoke_preauth_code(self, request_obj: Oid4vciSession) -> None:
        """Makes a pre-authorized code unusable (it was redeemed or attacked)."""
        with self._requests_by_preauth_code_ref_lock:
            if request_obj.pre_authorized_code_ref:
                self._requests_by_preauth_code_ref.pop(request_obj.pre_authorized_code_ref, None)
        with self._requests_by_preauth_code_lock:
            if request_obj.pre_authorized_code:
                self._requests_by_preauth_code.pop(request_obj.pre_authorized_code, None)

    def update_tx_code(self, session_id: str, tx_code: int):
        """
        Updates the 'tx_code'. Only the primary dictionary needs to be locked.
        The type hint is now 'int'.
        """
        with self._requests_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                request_obj.tx_code = tx_code
                logger.debug(f"Updated tx_code for session_id {session_id}")
            else:
                logger.warning(
                    f"Attempted to update tx_code for non-existent session_id: {session_id}"
                )

    def update_frontend_id(self, session_id: str, frontend_id: str):
        """
        Updates the 'frontend_id'. Only the primary dictionary needs to be locked.
        """
        with self._requests_lock:
            request_obj = self._requests.get(session_id)
            if request_obj:
                request_obj.frontend_id = frontend_id
                logger.debug(
                    f"Updated frontend_id for session_id {session_id} to: {frontend_id}"
                )
            else:
                logger.warning(
                    f"Attempted to update frontend_id for non-existent session_id: {session_id}"
                )

    def get_request(self, session_id: str) -> Optional[Oid4vciSession]:
        """
        Retrieves an Oid4vciRequest object by its session ID.
        Locks the primary dictionary for a safe read.
        """
        with self._requests_lock:
            request_obj = self._requests.get(session_id)
            if request_obj and not self.is_expired(request_obj):
                return request_obj
            elif request_obj and self.is_expired(request_obj):
                logger.debug(
                    f"Request with session_id {session_id} found but has expired. Removing."
                )
                # If a request is expired, we need to clean it up from all managers.
                # This requires acquiring all locks to ensure a complete, atomic removal.
                self._remove_request_from_all_managers(request_obj)
        return None

    def get_request_by_uri(self, request_uri: str) -> Optional[Oid4vciSession]:
        """
        Retrieves a request by its URI.
        Locks the URI index for a safe read.
        """
        return self._lookup(self._requests_by_uri, self._requests_by_uri_lock, request_uri)

    def get_request_by_code(self, code: str) -> Optional[Oid4vciSession]:
        """
        Retrieves a request by its code.
        Locks the code index for a safe read.
        """
        return self._lookup(self._requests_by_code, self._requests_by_code_lock, code)

    def get_request_by_preauth_code(
        self, pre_authorized_code: str
    ) -> Optional[Oid4vciSession]:
        """
        Retrieves a request by its pre-authorized code.
        Locks the pre-auth code index.
        """
        return self._lookup(self._requests_by_preauth_code, self._requests_by_preauth_code_lock, pre_authorized_code)

    def get_request_by_preauth_code_ref(
        self, pre_authorized_code_ref: str
    ) -> Optional[Oid4vciSession]:
        """
        Retrieves a request by its pre-authorized code ref.
        Locks the pre-auth code ref index.
        """
        return self._lookup(self._requests_by_preauth_code_ref, self._requests_by_preauth_code_ref_lock, pre_authorized_code_ref)

    def get_request_by_refresh_token(
        self, refresh_token: str
    ) -> Optional[Oid4vciSession]:
        """
        Retrieves a request by its refresh token.
        Locks the refresh token index.
        """
        return self._lookup(self._requests_by_refresh_token, self._requests_by_refresh_token_lock, refresh_token)

    def _lookup(self, index: Dict, lock, key) -> Optional[Oid4vciSession]:
        """Reads ``index[key]``; drops the request when it has expired.

        The index lock is released before the removal, which takes every lock
        starting with ``_requests_lock``: holding an index lock while waiting
        for ``_requests_lock`` deadlocked against ``clean_expired_requests``.
        """
        with lock:
            request_obj = index.get(key)
        if request_obj is None:
            return None
        if not self.is_expired(request_obj):
            return request_obj
        logger.debug("Request %s has expired. Removing.", request_obj.session_id)
        self._remove_request_from_all_managers(request_obj)
        return None

    def is_expired(self, request_obj: Oid4vciSession) -> bool:
        """
        Checks if an Oid4vciRequest object has expired.
        This method does not modify any shared state and therefore does not need a lock.
        """
        return datetime.datetime.now(datetime.timezone.utc) >= request_obj.expiry_time

    def _remove_request_from_all_managers(self, request_obj: Oid4vciSession):
        """
        A helper method to remove a request from all internal dictionaries.
        This critical operation requires acquiring all locks to ensure a complete
        and atomic removal, preventing partial state corruption.
        """
        with self._requests_lock, self._requests_by_uri_lock, self._requests_by_code_lock, self._requests_by_preauth_code_lock, self._requests_by_preauth_code_ref_lock, self._requests_by_refresh_token_lock:
            if request_obj.session_id in self._requests:
                del self._requests[request_obj.session_id]
            if (
                request_obj.request_uri
                and request_obj.request_uri in self._requests_by_uri
            ):
                del self._requests_by_uri[request_obj.request_uri]
            if request_obj.code and request_obj.code in self._requests_by_code:
                del self._requests_by_code[request_obj.code]
            if (
                request_obj.pre_authorized_code
                and request_obj.pre_authorized_code in self._requests_by_preauth_code
            ):
                del self._requests_by_preauth_code[request_obj.pre_authorized_code]
            if (
                request_obj.pre_authorized_code_ref
                and request_obj.pre_authorized_code_ref
                in self._requests_by_preauth_code_ref
            ):
                del self._requests_by_preauth_code_ref[
                    request_obj.pre_authorized_code_ref
                ]
            if (
                request_obj.refresh_token
                and request_obj.refresh_token in self._requests_by_refresh_token
            ):
                del self._requests_by_refresh_token[request_obj.refresh_token]
            logger.debug(f"Removed all references for session_id: {request_obj.session_id}")

    def _clean_if_due(self):
        """Runs :meth:`clean_expired_requests` at most every ``CLEAN_INTERVAL`` seconds."""
        now = time.monotonic()
        if now - self._last_clean >= self.CLEAN_INTERVAL:
            self._last_clean = now
            self.clean_expired_requests()

    def clean_expired_requests(self):
        """
        Removes all expired Oid4vciRequest objects from the manager.
        This operation modifies all dictionaries, so it must acquire all locks
        to ensure thread safety during the cleanup process.
        """
        # A single nested `with` statement safely acquires and releases all locks
        # for this complex, multi-dictionary operation.
        with self._requests_lock, self._requests_by_uri_lock, self._requests_by_code_lock, self._requests_by_preauth_code_lock, self._requests_by_preauth_code_ref_lock, self._requests_by_refresh_token_lock:
            expired_session_ids = [
                session_id
                for session_id, request_obj in self._requests.items()
                if self.is_expired(request_obj)
            ]
            for session_id in expired_session_ids:
                request_obj = self._requests[session_id]
                logger.debug(
                    f"Cleaning up expired request: {session_id} (URI: {request_obj.request_uri})"
                )
                self._remove_request_from_all_managers(request_obj)

            if expired_session_ids:
                logger.debug(f"Cleaned up {len(expired_session_ids)} expired requests.")
            else:
                logger.debug("No expired requests to clean up.")

    def get_active_requests_count(self) -> int:
        """
        Returns the number of active requests.
        Only needs to lock the primary requests dictionary for a safe read.
        """
        with self._requests_lock:
            return len(self._requests)
