"""Security helpers shared by the views.

* :func:`session_token` signs the issuance session handed to the issuer
  backend, so the backend can trust ``session_id`` and the requested
  credentials instead of reading them from the query string.
* :func:`backend_api_key_error` protects the endpoints only the issuer
  backend may call (``/preauth_generate``).
* :func:`valid_redirect_uri` decides which wallet redirect URIs a client
  may register.
"""

import hashlib
import hmac
import ipaddress
import re
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from cryptojwt.jwt import JWT
from flask import current_app, jsonify, request

#: ``aud`` of the session token; the issuer backend checks it.
SESSION_TOKEN_AUDIENCE = "eudiw-issuer-backend"
#: Seconds the backend has to accept the session token.
SESSION_TOKEN_LIFETIME = 300
#: Placeholder keys from the example configuration; treated as unset.
PLACEHOLDER_API_KEYS = frozenset({"change-me", "changeme", "secret"})


def session_token(
    session_id: str,
    scope: Optional[str] = None,
    authorization_details: Any = None,
    frontend_id: Optional[str] = None,
) -> str:
    """Signs the issuance session handed to the issuer backend.

    Args:
        session_id: Issuance session id.
        scope: Requested scope.
        authorization_details: Requested authorization details.
        frontend_id: Frontend that started the flow.

    Returns:
        A short-lived ES256 JWT signed with the OP key (see ``/static/jwks.json``).
    """
    context = current_app.server.get_context()
    claims: Dict[str, Any] = {"session_id": session_id}
    if scope:
        claims["scope"] = scope
    if authorization_details:
        claims["authorization_details"] = authorization_details
    if frontend_id:
        claims["frontend_id"] = frontend_id
    signer = JWT(context.keyjar, iss=context.issuer, sign_alg="ES256", lifetime=SESSION_TOKEN_LIFETIME)
    return signer.pack(payload=claims, aud=[SESSION_TOKEN_AUDIENCE])


#: Redirect URI the server registers for its own pre-authorized code request.
PREAUTH_REDIRECT_URI = "preauth"
#: Schemes that run code or read local data in a browser.
_UNSAFE_SCHEMES = frozenset({"javascript", "data", "vbscript", "file", "blob", "about"})


def valid_redirect_uri(uri: Optional[str]) -> bool:
    """Checks a wallet redirect URI, following RFC 8252 (OAuth for native apps).

    Accepted: an ``https`` URL with a host, an ``http`` URL on a loopback
    address, or any other private-use scheme (e.g.
    ``eu.europa.ec.euidi://authorization``, ``asitplus-wallet://...``) except
    those that run code or read local data in a browser. RFC 8252 7.1 only
    recommends reverse-domain schemes, and wallets in use do not follow it. A
    fragment is never allowed (RFC 6749 3.1.2).

    Args:
        uri: The ``redirect_uri`` a client sent.

    Returns:
        True when the URI may be registered.
    """
    if not uri or not isinstance(uri, str) or uri != uri.strip():
        return False
    if any(ord(c) < 0x21 or c == "\\" for c in uri):
        return False
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    scheme = parts.scheme.lower()
    if not scheme or parts.fragment or "#" in uri or scheme in _UNSAFE_SCHEMES:
        return False
    if scheme == "https":
        return bool(parts.hostname) and not parts.username and not parts.password
    if scheme == "http":
        return _is_loopback(parts.hostname) and not parts.username and not parts.password
    return True


def _is_loopback(host: Optional[str]) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class OneTimeUse:
    """Remembers values (by hash) until they expire, to refuse a second use.

    In memory: run a single process, or replace it with a shared store.
    """

    def __init__(self, max_entries: int = 100_000):
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def first_use(self, value: str, ttl: int) -> bool:
        """Returns True the first time ``value`` is seen within ``ttl`` seconds."""
        key = hashlib.sha256(value.encode()).hexdigest()
        now = time.time()
        with self._lock:
            if len(self._seen) >= self._max_entries:
                self._purge_expired(now)
            if self._seen.get(key, 0) > now:
                return False
            if len(self._seen) >= self._max_entries:
                return False  # full of live entries: fail closed
            self._seen[key] = now + ttl
            return True

    def purge_expired(self) -> int:
        """Forgets expired values; returns how many were removed."""
        with self._lock:
            return self._purge_expired(time.time())

    def _purge_expired(self, now: float) -> int:
        """Call with the lock held."""
        before = len(self._seen)
        self._seen = {k: exp for k, exp in self._seen.items() if exp > now}
        return before - len(self._seen)


#: Authentication hand-off tokens already redeemed at /verify/user.
used_authn_tokens = OneTimeUse()


#: Frontend ids are a path segment of their issuer identifier.
FRONTEND_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
#: First path segments of the shared routes, which no frontend id may take.
RESERVED_FRONTEND_IDS = frozenset({"static", "keys", "verify", "introspection", "preauth_generate"})


def load_frontends(frontends) -> tuple:
    """Checks the ``frontends`` setting: the ids of the issuer frontends.

    Args:
        frontends: List of frontend ids (the issuer backend's
            ``frontend.frontends_config`` keys).

    Returns:
        The ids, in order, without duplicates.

    Raises:
        ValueError: When the list is empty or an id is not a plain path
            segment (letters, digits, ``_``, ``-``) or is reserved.
    """
    ids = list(frontends or [])
    if not ids:
        raise ValueError("frontends: at least one frontend id is required")
    for frontend_id in ids:
        if (
            not isinstance(frontend_id, str)
            or not FRONTEND_ID_PATTERN.match(frontend_id)
            or frontend_id in RESERVED_FRONTEND_IDS
        ):
            raise ValueError(f"frontends: invalid frontend id {frontend_id!r}")
    return tuple(dict.fromkeys(ids))


def configure_frontends(app, frontends) -> None:
    """Makes this server the authorization server of each frontend.

    Each frontend has its own issuer, ``<issuer>/<frontend id>``: the DPoP
    ``htu`` of its token and pushed authorization endpoints are allowed (a
    request accepts only those of its own issuer, ``CURRENT_ISSUER``), and
    the signing keys are registered under its issuer, so the server verifies
    the tokens it issued as that issuer (introspection, refresh).
    """
    app.frontends = load_frontends(frontends)
    context = app.server.get_context()
    issuers = [f"{context.issuer}/{frontend_id}" for frontend_id in app.frontends]
    dpop = getattr(context, "add_on", {}).get("dpop")
    if dpop is not None:
        dpop["allowed_htu"] = [f"{issuer}/token" for issuer in issuers]
        dpop["par_allowed_htu"] = [f"{issuer}/pushed_authorization" for issuer in issuers]
    keyjar = context.keyjar
    own_keys = keyjar.export_jwks(private=True)
    for issuer in issuers:
        keyjar.import_jwks(own_keys, issuer)


def trust_proxies(app, proxies: int) -> None:
    """Trusts ``proxies`` reverse proxies (or a platform ingress) for the
    client address, scheme and host (``X-Forwarded-For/-Proto/-Host``)."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    if proxies > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies, x_host=proxies)


#: Endpoints where the wallet authenticates as a client.
WALLET_CLIENT_ENDPOINTS = ("pushed_authorization", "token")


def configure_client_authentication(app, require_wallet_attestation: bool = True) -> None:
    """Sets how wallets authenticate at the PAR and token endpoints.

    OpenID4VCI only RECOMMENDS wallet attestation (section 13.2). With it
    required (the default), only ``wallet_attestation`` is accepted. Otherwise
    a wallet may also be a public client; an attestation that is sent is still
    verified first, and a failing one is rejected, never ignored.
    """
    methods = ["wallet_attestation"]
    if not require_wallet_attestation:
        methods += ["public", "none"]
    for name in WALLET_CLIENT_ENDPOINTS:
        endpoint = app.server.get_endpoint(name)
        if endpoint is not None:
            endpoint.client_authn_method = list(methods)


def backend_api_key_error():
    """Checks the ``X-Api-Key`` header sent by the issuer backend.

    Returns:
        ``None`` when the key matches, otherwise the error response: ``503``
        when no key is configured, ``401`` for a missing or wrong key.
    """
    expected = getattr(current_app, "backend_api_key", None)
    if not expected or str(expected) in PLACEHOLDER_API_KEYS:
        current_app.logger.error("backend_api_key is not configured")
        return jsonify({"error": "service_unavailable", "error_description": "API key not configured"}), 503
    candidate = request.headers.get("X-Api-Key") or ""
    if not hmac.compare_digest(candidate.encode(), str(expected).encode()):
        # The matched route, not the raw (client-controlled) path.
        current_app.logger.warning(f"Rejected {request.url_rule.rule}: missing or invalid X-Api-Key")
        return jsonify({"error": "unauthorized", "error_description": "Missing or invalid API key"}), 401
    return None


#: Default limit per client address for each endpoint. Introspection and
#: /preauth_generate are not limited: only the issuer backend calls them (API
#: key), from one address, so a per-address limit would cap all users together;
#: the backend limits its own user-facing endpoints.
ENDPOINT_LIMITS = {
    "oidc_op.token": "60 per minute",
    "oidc_op.par_endpoint": "30 per minute",
    "oidc_op.authorization": "30 per minute",
    "oidc_op.verify_user": "30 per minute",
}


def init_rate_limits(app, settings=None):
    """Applies per-client rate limits (``429`` when exceeded).

    Args:
        app: The Flask application, after the views are registered.
        settings: ``rate_limiting`` configuration: ``enabled`` (default
            true), ``storage_uri`` (default ``memory://``),
            ``trusted_proxies`` (reverse proxies whose ``X-Forwarded-For``
            is trusted; 1 behind nginx), ``forwarders`` and ``limits``
            overrides.

            ``forwarders`` lists the addresses of services that relay
            wallet requests and name the wallet in ``X-Forwarded-For``.
            Their requests are limited per wallet address; without this
            every relayed request shares the relay's limit. Only these
            peers can choose the key.

    Returns:
        The limiter, or ``None`` when disabled.
    """
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    settings = settings or {}
    if settings.get("enabled", True) is False:
        app.logger.warning("Rate limiting is disabled")
        return None
    proxies = int(settings.get("trusted_proxies", 0) or 0)

    def too_many_requests(limit):
        app.logger.warning(f"Rate limit exceeded: {limit.limit}")
        return jsonify({"error": "too_many_requests", "error_description": "Rate limit exceeded"}), 429

    forwarders = frozenset(settings.get("forwarders") or ())

    def client_address():
        """Rate limit key: the wallet's address, also behind a forwarder."""
        address = get_remote_address()
        if address in forwarders:
            # The entry the forwarder added: before those of trusted_proxies.
            hops = [h.strip() for h in request.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
            if len(hops) > proxies:
                return hops[-(proxies + 1)]
        return address

    limiter = Limiter(
        client_address,
        app=app,
        storage_uri=settings.get("storage_uri", "memory://"),
        headers_enabled=True,
        on_breach=too_many_requests,
    )
    for endpoint, limit in {**ENDPOINT_LIMITS, **(settings.get("limits") or {})}.items():
        view = app.view_functions.get(endpoint)
        if view is not None:
            app.view_functions[endpoint] = limiter.limit(limit)(view)
    return limiter


#: Parameter / header names whose values are secrets and never logged.
SENSITIVE_NAMES = frozenset(
    {
        "code", "code_verifier", "access_token", "refresh_token", "id_token", "token",
        "client_assertion", "client_secret", "pre-authorized_code", "pre_authorized_code",
        "tx_code", "authorization", "dpop", "cookie", "set-cookie", "jws",
        "oauth-client-attestation", "oauth-client-attestation-pop", "x-api-key", "value",
    }
)


def redact(value):
    """Returns a copy of ``value`` safe to log: secret fields become ``<redacted>``.

    Dicts (and Message objects), lists and URL-like strings with secrets in the
    query are handled; header lists of ``{"name", "value"}`` (cookies) too.
    """
    if hasattr(value, "to_dict") and not isinstance(value, dict):
        try:
            value = value.to_dict()
        except Exception:
            return "<unloggable>"
    if isinstance(value, dict):
        if set(value) >= {"name", "value"}:
            return {"name": value.get("name"), "value": "<redacted>"}
        return {k: "<redacted>" if str(k).lower() in SENSITIVE_NAMES else redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str) and value.lstrip().startswith("{"):
        import json

        try:
            return json.dumps(redact(json.loads(value)))
        except ValueError:
            return "<unloggable>"
    if isinstance(value, str) and "=" in value and ("?" in value or "&" in value):
        from urllib.parse import parse_qsl, urlsplit

        query = urlsplit(value).query if "?" in value else value
        if any(k.lower() in SENSITIVE_NAMES for k, _ in parse_qsl(query)):
            return value.split("?", 1)[0] + "?<redacted query>" if "?" in value else "<redacted>"
    return value
