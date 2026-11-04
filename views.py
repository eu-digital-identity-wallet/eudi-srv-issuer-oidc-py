import copy
import json
import secrets
import sys
import threading
import traceback
from typing import Optional, Union
from uuid import uuid4

import requests

from cryptojwt.exception import VerificationError
from flask import Blueprint
from flask import Response
from flask import current_app
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify, abort
from flask.helpers import make_response
from flask.helpers import send_from_directory
import urllib.parse

from idpyoidc.client.oauth2.introspection import Introspection
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
import werkzeug

from idpyoidc.server.exception import FailedAuthentication
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import UnAuthorizedClient
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.util import CURRENT_ISSUER

# logger = logging.getLogger(__name__)

#: Every route; registered under the path of the issuer (e.g. /oidc).
oidc_op_views = Blueprint("oidc_op", __name__)
from application import request_manager
from security import (
    PREAUTH_REDIRECT_URI,
    backend_api_key_error,
    redact,
    session_token,
    used_authn_tokens,
    valid_redirect_uri,
)


def frontend_issuer(frontend_id: str) -> str:
    """The issuer identifier this server has for a frontend: ``<issuer>/<frontend_id>``."""
    return f"{current_app.server.get_context().issuer}/{frontend_id}"


def use_frontend(frontend_id: Optional[str]) -> bool:
    """Answers the current request as ``frontend_id``'s issuer.

    Sets :data:`idpyoidc.server.util.CURRENT_ISSUER`, read by the authorization
    response ``iss``, the token ``iss`` and the client attestation PoP ``aud``
    checks. Reset at the end of the request (:func:`reset_frontend`).

    Returns:
        False for a frontend this server does not know.
    """
    if frontend_id not in current_app.frontends:
        return False
    g.frontend_id = frontend_id
    g.issuer_token = CURRENT_ISSUER.set(frontend_issuer(frontend_id))
    return True


def reset_frontend(exc=None):
    """Teardown: the next request on this thread starts without an issuer."""
    issuer_token = g.pop("issuer_token", None)
    if issuer_token is not None:
        CURRENT_ISSUER.reset(issuer_token)


@oidc_op_views.url_value_preprocessor
def _frontend_from_path(endpoint, values):
    """``/<frontend_id>/...`` routes: an unknown frontend is not found."""
    if values and "frontend_id" in values:
        if not use_frontend(values.pop("frontend_id")):
            abort(404)


def _other_frontend(current_request) -> bool:
    """Tells whether a stored request belongs to another frontend than the path's."""
    return getattr(current_request, "frontend_id", None) != g.get("frontend_id")


def _add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    kwargs = {k: v for k, v in cookie_spec.items() if k not in ("name",)}
    kwargs["path"] = "/"
    kwargs["samesite"] = "Lax"
    kwargs["secure"] = True
    kwargs["httponly"] = True
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)


@oidc_op_views.route("/static/<path:path>")
def send_js(path):
    return send_from_directory("static", path)


@oidc_op_views.route("/keys/<jwks>")
def keys(jwks):
    # Only the published JWKS files; send_from_directory refuses paths that
    # leave the folder and answers 404 for a missing file (was a 500).
    if not jwks.endswith(".json"):
        abort(404)
    return send_from_directory("static", jwks, mimetype="application/json")


@oidc_op_views.route("/")
def index():
    return render_template("index.html")


# def add_headers_and_cookie(resp, info):
#     return resp


def do_response(endpoint, req_args, error="", **args) -> Response:
    info = endpoint.do_response(request=req_args, error=error, **args)
    _log = current_app.logger
    _log.debug("do_response: {}".format(redact(info)))

    try:
        _response_placement = info["response_placement"]
    except KeyError:
        _response_placement = endpoint.response_placement

    _log.debug("response_placement: {}".format(_response_placement))

    if error:
        if _response_placement == "body":
            _log.info("Error Response: {}".format(redact(info["response"])))
            _http_response_code = info.get("response_code", 400)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info("Error redirect issued")
            resp = redirect(info["response"])
    else:
        if _response_placement == "body":
            _log.debug("Response: {}".format(redact(info["response"])))
            _http_response_code = info.get("response_code", 200)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info("Redirect issued")
            resp = redirect(info["response"])

    for key, value in info["http_headers"]:
        resp.headers[key] = value

    if "cookie" in info:
        add_cookie(resp, info["cookie"])

    return resp


def _issued_code(args: dict, label: str):
    """Reads the authorization code from an ``authz_part2`` result.

    ``authz_part2`` reports errors inside its result: in ``response_args``,
    or, for ``response_mode=form_post``, only as the HTML form in
    ``response_msg`` (no ``response_args``).

    Args:
        args: The ``authz_part2`` result.
        label: Session description for the log.

    Returns:
        ``(code, None)``, or ``(None, error response)``: 400 with the error
        ``authz_part2`` reported, 500 ``server_error`` when it issued no code.
    """
    response_args = args.get("response_args") if isinstance(args, dict) else None
    response_dict = response_args.to_dict() if response_args is not None else {}

    if "error" in response_dict:
        current_app.logger.error(f"authz_part2 returned error for {label}: {response_dict}")
        return None, make_response(json.dumps(response_dict), 400)

    code = response_dict.get("code")
    if not code:
        keys = sorted(args) if isinstance(args, dict) else type(args).__name__
        current_app.logger.error(f"authz_part2 issued no code for {label}: {response_dict or keys}")
        return None, make_response(
            json.dumps({"error": "server_error", "error_description": "no code issued"}),
            500,
        )
    return code, None


# Error redirection to the wallet during authentication
def authentication_error_redirect(jws_token, error, error_description):
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        auth_args = authn_method.unpack_token(jws_token)
    except:
        return make_response(
            json.dumps(
                {"error": "invalid_request", "error_description": "Cookie Lost"}
            ),
            400,
        )

    if error is None:
        error = "invalid_request"

    if error_description is None:
        error_description = "invalid_request"

    params = {"error": error, "error_description": error_description}
    # RFC 6749 4.1.2.1: the state of the authorization request comes back.
    state = urllib.parse.parse_qs(auth_args.get("query") or "").get("state")
    if state:
        params["state"] = state[0]
    return_uri = auth_args["return_uri"]
    separator = "&" if urllib.parse.urlsplit(return_uri).query else "?"
    return redirect(return_uri + separator + urllib.parse.urlencode(params), code=302)


# Error redirection to the wallet during authentication without jws_token
def auth_error_redirect(return_uri, error, error_description=None, client_id=None, state=None):
    """Sends an OAuth error to the client's redirect URI.

    Redirects only to a URI registered for ``client_id`` (RFC 6749 4.1.2.1);
    otherwise answers with the error as JSON, so the endpoint cannot be used
    to send a browser anywhere (open redirect).
    """
    error_msg = {"error": error}
    if error_description is not None:
        error_msg["error_description"] = error_description

    registered = []
    if client_id:
        registered = current_app.server.get_context().cdb.get(client_id, {}).get("redirect_uris", [])
        registered = [uri[0] if isinstance(uri, (list, tuple)) else uri for uri in registered]
    # The redirect is built from the registered copy, never from the request's.
    target = next((uri for uri in registered if return_uri and uri == return_uri), None)
    if target and valid_redirect_uri(target):
        params = dict(error_msg)
        if state:
            # RFC 6749 4.1.2.1: the state of the authorization request comes back.
            params["state"] = state
        separator = "&" if urllib.parse.urlsplit(target).query else "?"
        return redirect(target + separator + urllib.parse.urlencode(params), code=302)

    status = 500 if error == "server_error" else 400
    return make_response(json.dumps(error_msg), status, {"Content-Type": "application/json"})


def _session_matches_request(session_id, authz_request) -> bool:
    """Tells whether an issuance session belongs to an authorization request.

    Args:
        session_id: Session id sent back by the issuer backend.
        authz_request: Authorization request from the signed token.

    Returns:
        True when the session was created for this client, redirect URI,
        state and PKCE challenge.
    """
    current_request = request_manager.get_request(session_id=session_id)
    if current_request is None:
        return False
    for name in ("client_id", "redirect_uri", "state", "code_challenge"):
        stored = getattr(current_request, name, None)
        if (stored or None) != (authz_request.get(name) or None):
            return False
    return True


def verify(authn_method):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """
    # kwargs = dict([(k, v) for k, v in request.form.items()])

    try:
        username = authn_method.verify(username=request.args.get("username"))

        auth_args = authn_method.unpack_token(request.args.get("token"))
    except:
        current_app.logger.error(
            "Authorization verification: username or jws_token not found"
        )
        if "jws_token" in request.args:
            return authentication_error_redirect(
                jws_token=request.args.get("jws_token"),
                error="invalid_request",
                error_description="Authentication verification Error",
            )
        else:
            return "Internal Server Error", 500
            # return render_template("misc/500.html", error="Authentication verification Error")

    authz_request = AuthorizationRequest().from_urlencoded(auth_args["query"])

    # The token proves which authorization request is being completed; the
    # username (issuance session) must be the one created for that request,
    # or anyone holding a token could complete it with another session.
    if not _session_matches_request(username, authz_request):
        current_app.logger.warning(
            f"Authorization verification: session {username} does not match the token's request"
        )
        return make_response(
            json.dumps(
                {"error": "invalid_request", "error_description": "Session mismatch"}
            ),
            400,
        )

    # One code per authentication: the token cannot be redeemed again.
    if not used_authn_tokens.first_use(
        request.args.get("token", ""), getattr(authn_method, "token_lifetime", 1800)
    ):
        current_app.logger.warning(
            f"Authorization verification: token already used for session {username}"
        )
        return make_response(
            json.dumps({"error": "invalid_request", "error_description": "Token already used"}),
            400,
        )

    # The authorization response names the issuer of the frontend the
    # wallet started at (RFC 9207).
    if not use_frontend(getattr(request_manager.get_request(session_id=username), "frontend_id", None)):
        current_app.logger.warning(f"Authorization verification: session {username} has no known frontend")
        return _oauth_error("invalid_request", "Unknown frontend")

    endpoint = current_app.server.get_endpoint("authorization")

    _session_id = endpoint.create_session(
        authz_request,
        username,
        auth_args["authn_class_ref"],
        auth_args["iat"],
        authn_method,
    )

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    code, error = _issued_code(args, f"session {username}")
    if error is not None:
        return error

    request_manager.update_code(session_id=username, code=code)

    return do_response(endpoint, request, **args)


@oidc_op_views.route("/verify/user", methods=["GET", "POST"])
def verify_user():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        return render_template("error.html", title=str(exc))


#: Metadata names (RFC 8414 registry) of the client authentication methods.
_AUTH_METHOD_NAMES = {"wallet_attestation": "attest_jwt_client_auth", "public": "none", "none": "none"}


#: Signature algorithms accepted for wallet attestations and their PoPs.
_ATTESTATION_ALGS = ["ES256", "ES384", "ES512"]
#: Discovery documents served (RFC 8414 and OpenID Connect Discovery).
METADATA_SERVICES = ("oauth-authorization-server", "openid-configuration")


def metadata_document(frontend_id: str) -> dict:
    """The authorization server metadata of a frontend's issuer.

    Built from the running configuration, so it states what this server
    actually requires (PAR, PKCE, DPoP algorithms, client authentication).
    """
    context = current_app.server.get_context()
    issuer = frontend_issuer(frontend_id)
    info = context.provider_info
    document = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorization",
        "pushed_authorization_request_endpoint": f"{issuer}/pushed_authorization",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{context.issuer}/static/jwks.json",
        "require_pushed_authorization_requests": bool(
            getattr(current_app, "require_pushed_authorization_requests", True)
        ),
        "response_types_supported": ["code"],
        "response_modes_supported": list(info.get("response_modes_supported") or ["query"]),
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "refresh_token",
        ],
        # RFC 9207: the authorization response names this issuer.
        "authorization_response_iss_parameter_supported": True,
        "client_attestation_signing_alg_values_supported": list(_ATTESTATION_ALGS),
        "client_attestation_pop_signing_alg_values_supported": list(_ATTESTATION_ALGS),
        # OpenID4VCI 1.0 section 12.3: whether a wallet may use a
        # pre-authorized code without client authentication.
        "pre-authorized_grant_anonymous_access_supported": not getattr(
            current_app, "require_wallet_attestation", True
        ),
        # OpenID Connect Discovery requires these two.
        "subject_types_supported": list(info.get("subject_types_supported") or ["public"]),
        "id_token_signing_alg_values_supported": list(info.get("id_token_signing_alg_values_supported") or ["ES256"]),
    }
    dpop = getattr(context, "add_on", {}).get("dpop")
    if dpop:
        document["dpop_signing_alg_values_supported"] = list(dpop["algs_supported"])
    pkce = getattr(context, "add_on", {}).get("pkce")
    if pkce:
        document["code_challenge_methods_supported"] = list(pkce["code_challenge_methods"])
    token_endpoint = current_app.server.get_endpoint("token")
    if token_endpoint is not None and token_endpoint.client_authn_method:
        names = [_AUTH_METHOD_NAMES.get(m, m) for m in token_endpoint.client_authn_method]
        document["token_endpoint_auth_methods_supported"] = list(dict.fromkeys(names))
    return document


def _metadata_response(service, frontend_id):
    if service not in METADATA_SERVICES or frontend_id not in current_app.frontends:
        # RFC 8615: a well-known URI that is not defined here does not exist.
        abort(404)
    return jsonify(metadata_document(frontend_id))


@oidc_op_views.route("/<frontend_id>/.well-known/<service>")
def well_known(service):
    """Metadata at ``<issuer>/.well-known/<service>`` (OpenID Connect Discovery)."""
    return _metadata_response(service, g.frontend_id)


def well_known_inserted(service, frontend_id):
    """Metadata at ``/.well-known/<service><issuer path>`` (RFC 8414 section 3.1).

    Registered at the host root by :func:`register_well_known`.
    """
    return _metadata_response(service, frontend_id)


def register_well_known(app, prefix: str) -> None:
    """Routes the RFC 8414 discovery URLs, which sit at the host root.

    Args:
        app: The Flask application.
        prefix: Path of the issuer (``/oidc``, or ``""``).
    """
    app.add_url_rule(
        f"/.well-known/<service>{prefix}/<frontend_id>",
        endpoint="well_known_inserted",
        view_func=well_known_inserted,
    )


def _oauth_error(error, description, status=400):
    """An OAuth error response as JSON (RFC 6749 section 5.2)."""
    return make_response(
        json.dumps({"error": error, "error_description": description}),
        status,
        {"Content-Type": "application/json"},
    )


def _registration_error(description):
    """400 ``invalid_request`` as JSON: never redirect to an unchecked URI."""
    return _oauth_error("invalid_request", description)


#: The only authorization details type this server knows (OpenID4VCI 1.0 section 5.1.1).
_AUTHORIZATION_DETAILS_TYPES = ("openid_credential",)


def _authorization_details_error(details):
    """``invalid_authorization_details`` (RFC 9396 section 5) for a value that
    is not a non-empty array of objects of a known type, else None."""
    if (
        not isinstance(details, list)
        or not details
        or not all(isinstance(d, dict) and d.get("type") in _AUTHORIZATION_DETAILS_TYPES for d in details)
    ):
        return _oauth_error(
            "invalid_authorization_details",
            "authorization_details must be an array of openid_credential objects",
        )
    return None


#: Serialises client registrations. They read, change and write the shared
#: client database; concurrent requests for one client could otherwise lose a
#: redirect URI or read a half-written client entry.
_registration_lock = threading.RLock()


def _no_restore():
    return None


def dynamic_registration(client_id, redirect_uri, internal=False):
    """Registers ``redirect_uri`` for ``client_id`` before an authorization request.

    Only RFC 8252 redirect URIs are accepted (``security.valid_redirect_uri``);
    the ``preauth`` placeholder only for the server's own pre-authorized code
    request (``internal=True``).

    A redirect URI the client already has changes nothing. A new one is added
    to a copy of the client entry, which then replaces the entry in one
    assignment, so concurrent requests never see it half-written. Only an
    unknown client goes through the registration endpoint.

    Returns:
        ``(error_response, restore)``: an error response, or None; and a
        function that takes back what this call added, for when the request
        that follows fails (an unauthenticated request must not change a
        registered client).
    """
    _context = current_app.server.get_context()
    if not client_id or not isinstance(client_id, str):
        return _registration_error("client_id is required"), _no_restore
    if internal:
        if redirect_uri != PREAUTH_REDIRECT_URI:
            return _registration_error("invalid redirect_uri"), _no_restore
    elif not valid_redirect_uri(redirect_uri):
        # Nothing the client sent is logged (log injection).
        current_app.logger.warning("Rejected a redirect_uri that is not a safe native-app URI")
        return _registration_error("invalid redirect_uri"), _no_restore

    registration = current_app.server.get_endpoint("registration")
    try:
        # The form the registration endpoint stores: (base, query).
        new_uri = tuple(
            registration.verify_redirect_uris({"application_type": "native", "redirect_uris": [redirect_uri]})[0]
        )
    except Exception:
        return _registration_error("invalid redirect_uri"), _no_restore

    def registered(entry):
        return [tuple(uri) for uri in (entry or {}).get("redirect_uris", [])]

    with _registration_lock:
        entry = _context.cdb.get(client_id)
        if entry is not None:
            if new_uri in registered(entry):
                return None, _no_restore
            updated = copy.deepcopy(entry)
            updated["redirect_uris"] = list(entry.get("redirect_uris", [])) + [new_uri]
            _context.cdb[client_id] = updated
            created = False
        else:
            try:
                result = registration.process_request_authorization(client_id=client_id, redirect_uri=redirect_uri)
                if isinstance(result, ResponseMessage) and "error" in result:
                    raise ValueError(result.get("error_description") or result["error"])
            except Exception as e:
                current_app.logger.error(f"Error during client registration: {e}")
                _context.cdb.pop(client_id, None)
                return _registration_error("client registration failed"), _no_restore
            created = True

    def restore():
        with _registration_lock:
            entry = _context.cdb.get(client_id)
            if entry is None:
                return
            remaining = [uri for uri in entry.get("redirect_uris", []) if tuple(uri) != new_uri]
            if created and not remaining:
                _context.cdb.pop(client_id, None)
            else:
                updated = copy.deepcopy(entry)
                updated["redirect_uris"] = remaining
                _context.cdb[client_id] = updated

    return None, restore


@oidc_op_views.route("/<frontend_id>/authorization")
def authorization():
    # 1. Handle PAR Authorization Request

    if "request_uri" in request.args:
        request_uri = request.args.get("request_uri")

        # Errors before the pushed request is found are never redirected: no
        # redirect URI is known for them (RFC 6749 4.1.2.1).
        if not request_uri:
            current_app.logger.warning(
                "Authorization Request: 'request_uri' is missing from the request."
            )
            return _oauth_error("invalid_request", "request_uri is empty")

        current_request = request_manager.get_request_by_uri(request_uri)

        if not current_request or _other_frontend(current_request):
            current_app.logger.warning("Authorization Request: no pending request for the request_uri")
            # RFC 9126 section 4: an unknown or expired request_uri is invalid;
            # one pushed to another frontend's issuer is unknown to this one.
            return _oauth_error("invalid_request_uri", "unknown or expired request_uri")

        # RFC 9126 section 2.2: the request_uri is bound to the client that
        # pushed it; RFC 9101 section 5: client_id is required alongside it.
        if request.args.get("client_id") != current_request.client_id:
            current_app.logger.warning("Authorization Request: client_id does not match the pushed request")
            return _oauth_error("invalid_request", "client_id does not match the pushed authorization request")

        session_id = current_request.session_id

        current_app.logger.info(
            f"Session ID: {session_id}, Authorization Request (PAR), Payload: {redact(request.args.to_dict())}"
        )

        scope = current_request.scope
        authorization_details = getattr(current_request, "authorization_details", None) or None

        # RFC 9126 section 4: the authorization endpoint resolves the pushed
        # request itself; client_id and request_uri are all it needs.
        endpoint_args = {
            "client_id": current_request.client_id,
            "request_uri": current_request.request_uri,
        }
        # For error redirects to the wallet.
        authorization_args = {
            "client_id": current_request.client_id,
            "redirect_uri": current_request.redirect_uri,
        }
        if getattr(current_request, "state", None):
            authorization_args["state"] = current_request.state

    else:
        # HAIP requires PAR: only a pushed request has its client (WIA)
        # authenticated before the user is involved.
        if getattr(current_app, "require_pushed_authorization_requests", True):
            return _registration_error("a pushed authorization request (request_uri) is required")

        session_id = str(uuid4())

        current_app.logger.info(
            f"Session ID: {session_id}, Authorization Request (Non-PAR), Payload: {redact(request.args.to_dict())}"
        )

        try:
            client_id = request.args.get("client_id")
            redirect_uri = request.args.get("redirect_uri")
            response_type = request.args.get("response_type")
            scope = request.args.get("scope")
            code_challenge_method = request.args.get("code_challenge_method")
            code_challenge = request.args.get("code_challenge")
            authorization_details = request.args.get("authorization_details")
            state = request.args.get("state")
            issuer_state = request.args.get("issuer_state")

            if not all([client_id, redirect_uri, response_type]):
                current_app.logger.error(
                    "Missing required parameters for traditional authorization."
                )
                return _registration_error("Missing required parameters")

        except (
            Exception
        ) as e:  # Catch broad exception for simplicity, refine in production
            current_app.logger.error(f"Authorization request error: {e}")
            return make_response("Authorization request invalid parameters", 400)

        registration_error, _ = dynamic_registration(
            client_id=client_id, redirect_uri=redirect_uri
        )
        if registration_error is not None:
            return registration_error

        try:
            request_manager.add_request(
                client_id=client_id,
                redirect_uri=redirect_uri,
                response_type=response_type,
                scope=scope,
                code_challenge_method=code_challenge_method,
                code_challenge=code_challenge,
                authorization_details=authorization_details,
                session_id=session_id,
                state=state,
                issuer_state=issuer_state,
            )
            request_manager.update_frontend_id(session_id=session_id, frontend_id=g.frontend_id)
        except Exception as e:
            current_app.logger.error(f"Error adding request: {e}")
            return _oauth_error("server_error", "Failed to process request", 500)

        authorization_args = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
        }
        if scope:
            authorization_args["scope"] = scope
        if authorization_details:
            authorization_args["authorization_details"] = authorization_details
        if code_challenge and code_challenge_method:
            authorization_args["code_challenge"] = code_challenge
            authorization_args["code_challenge_method"] = code_challenge_method
        if state:
            authorization_args["state"] = state
        endpoint_args = authorization_args

    try:

        response = service_endpoint(
            current_app.server.get_endpoint("authorization"),
            get_args=endpoint_args,
        )

        _response = json.loads(response.get_data(as_text=True))

        if response.status_code != 200 or "error" in _response:
            # Rejected by the authorization endpoint (e.g. a request_uri that
            # was already used): the error goes to the registered redirect URI.
            current_app.logger.warning(f"Session ID: {session_id}, Authorization Request rejected")
            return auth_error_redirect(
                authorization_args.get("redirect_uri"),
                _response.get("error", "invalid_request"),
                _response.get("error_description"),
                client_id=authorization_args.get("client_id"),
                state=authorization_args.get("state"),
            )

        jws = _response.get("jws")

        redirect_url = (
            current_app.authorization_redirect_url
            + "?token="
            + jws
            + "&session_id="
            + session_id
        )
        if scope:
            redirect_url += "&scope=" + urllib.parse.quote(scope)

        if authorization_details:
            encoded_auth_details = urllib.parse.quote(json.dumps(authorization_details))
            redirect_url += "&authorization_details=" + encoded_auth_details

        frontend_id = g.frontend_id
        redirect_url += "&frontend_id=" + urllib.parse.quote(frontend_id)

        # Signed copy of the session id, scope and authorization details:
        # the backend trusts these claims, not the plain query parameters.
        redirect_url += "&session_token=" + session_token(
            session_id=session_id,
            scope=scope,
            authorization_details=authorization_details,
            frontend_id=frontend_id,
        )

        return redirect(redirect_url)

    except requests.exceptions.RequestException as e:
        current_app.logger.error(
            f"Error making internal request to authorization endpoint: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "internal_service_unavailable",
            client_id=authorization_args.get("client_id"),
            state=authorization_args.get("state"),
        )
    except Exception as e:
        current_app.logger.error(
            f"Unexpected error during authorization processing: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "unhandled_exception",
            client_id=authorization_args.get("client_id"),
            state=authorization_args.get("state"),
        )


@oidc_op_views.route("/<frontend_id>/token", methods=["GET", "PUT", "PATCH", "DELETE"])
@oidc_op_views.route("/<frontend_id>/pushed_authorization", methods=["GET", "PUT", "PATCH", "DELETE"])
@oidc_op_views.route("/introspection", methods=["GET", "PUT", "PATCH", "DELETE"])
def post_only():
    """405 for the POST-only endpoints (RFC 9126 section 2.3 for PAR).

    Answers in JSON with ``Allow: POST``, like the other OAuth errors.
    """
    response = make_response(
        json.dumps({"error": "invalid_request", "error_description": "the request must use POST"}),
        405,
        {"Content-Type": "application/json", "Allow": "POST"},
    )
    return response


@oidc_op_views.route("/<frontend_id>/pushed_authorization", methods=["POST"])
def par_endpoint():

    # Required parameters
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    response_type = request.form.get("response_type")  # Should be "code" as per OID4VCI

    # Validate required parameters
    if not all([client_id, redirect_uri, response_type]):
        return _oauth_error("invalid_request", "Missing required parameters")
    if "request_uri" in request.form:
        # RFC 9126 section 2.1: request_uri MUST NOT be pushed.
        return _oauth_error("invalid_request", "request_uri is not allowed in a pushed authorization request")

    # Optional parameters
    scope = request.form.get("scope")
    code_challenge_method = request.form.get("code_challenge_method")
    code_challenge = request.form.get("code_challenge")
    state = request.form.get("state")
    issuer_state = request.form.get("issuer_state")

    # issuer_state comes from the wallet (a credential offer): using it as the
    # session id would let a client choose or overwrite another session.
    session_id = str(uuid4())

    current_app.logger.info(
        f"Session ID: {session_id}, Pushed Authorization Request, Payload: {redact(request.form.to_dict())}"
    )

    authorization_details = None
    if "authorization_details" in request.form:
        try:
            authorization_details = json.loads(request.form["authorization_details"])
        except json.JSONDecodeError:
            return _oauth_error("invalid_request", "Invalid authorization_details JSON")
        details_error = _authorization_details_error(authorization_details)
        if details_error is not None:
            return details_error

    registration_error, restore_client = dynamic_registration(
        client_id=client_id, redirect_uri=redirect_uri
    )
    if registration_error is not None:
        return registration_error
    try:
        response = service_endpoint(
            current_app.server.get_endpoint("pushed_authorization")
        )
    except Exception as e:
        restore_client()
        current_app.logger.error(
            f"Error accessing pushed_authorization endpoint: {e}", exc_info=True
        )
        return _oauth_error(
            "server_error", "An internal server error occurred while processing the request.", 500
        )

    if response.status_code >= 400:
        # Client authentication (e.g. the WIA) or request validation failed.
        restore_client()
        current_app.logger.warning(f"Session ID: {session_id}, Pushed Authorization Request rejected")
        return response

    try:
        request_manager.add_request(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
            authorization_details=authorization_details,
            session_id=session_id,
            state=state,
            issuer_state=issuer_state,
        )

        request_manager.update_request_uri(
            session_id=session_id, request_uri=response.json["request_uri"]
        )

        # The frontend whose issuer the request was pushed to.
        request_manager.update_frontend_id(session_id=session_id, frontend_id=g.frontend_id)

    except Exception as e:
        current_app.logger.error(f"Error adding request: {e}")
        return _oauth_error("server_error", "Failed to process request", 500)

    current_app.logger.info(f", Session ID: {session_id}, Pushed Authorization Response")

    # RFC 9126 section 2.2: the request URI is returned with 201 Created.
    response.status_code = 201
    return response


""" @oidc_op_views.route("/token", methods=["GET", "POST"])
def token():
    return service_endpoint(current_app.server.get_endpoint("token")) """


def _refresh_token_lifetime():
    """Seconds a refresh token is valid for (the authz usage rules), or None."""
    _authz = current_app.server.get_context().authz
    _rules = _authz.grant_config.get("usage_rules", {}).get("refresh_token", {})
    return _rules.get("expires_in")


@oidc_op_views.route("/<frontend_id>/token", methods=["POST"])
def token():
    response = _token_response()
    # RFC 6749 section 5.1: responses carrying tokens must not be cached.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _token_response():
    req_args = dict([(k, v) for k, v in request.form.items()])

    grant_type = req_args.get("grant_type")
    response = None

    # A DPoP proof binds the tokens to the wallet key (RFC 9449). HAIP requires
    # it: a bearer token would work for anyone who copies it. The proof itself
    # (signature, typ, htm, htu, iat, single-use jti) is validated by the
    # idpy-oidc DPoP add-on, which also binds the grant and its tokens to the
    # key, refuses a refresh with another key and returns cnf.jkt at
    # /introspection.
    if request.headers.get("DPoP") is None and getattr(current_app, "require_dpop", True):
        current_app.logger.warning("Token request rejected: no DPoP proof")
        return make_response(
            jsonify({"error": "invalid_dpop_proof", "error_description": "A DPoP proof is required"}), 400
        )

    if not grant_type:
        # RFC 6749 section 5.2: a missing required parameter is invalid_request.
        return make_response(
            jsonify({"error": "invalid_request", "error_description": "missing grant_type"}), 400
        )

    if grant_type == "authorization_code":
        code = req_args.get("code")
        if not code:
            return make_response(
                jsonify({"error": "invalid_request", "error_description": "missing code"}),
                400,
            )

        current_request = request_manager.get_request_by_code(code)
        # A code is redeemed at the issuer of the frontend it was issued for.
        if current_request is None or _other_frontend(current_request):
            return make_response(jsonify({"error": "invalid_grant"}), 400)

        session_id = current_request.session_id

        current_app.logger.info(f", Session ID: {session_id}, Token Request")

        # Pass the request form data to service_endpoint for accurate processing
        response_obj = service_endpoint(current_app.server.get_endpoint("token"))

        response_data = response_obj.get_data()

        if response_obj.status_code != 200:
            # The endpoint's own response: a JSON error keeps its Content-Type.
            return response_obj

        response_json = json.loads(response_data)

        current_app.logger.info(f", Session ID: {session_id}, Token Response issued")

        if "access_token" in response_json:
            request_manager.update_access_token(
                session_id=session_id, access_token=response_json["access_token"]
            )

        if "refresh_token" in response_json:
            request_manager.update_refresh_token(
                session_id=session_id,
                refresh_token=response_json["refresh_token"],
                lifetime_seconds=_refresh_token_lifetime(),
            )

        return jsonify(response_json)  # Return as JSON

    elif grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        pre_authorized_code_from_request = req_args.get("pre-authorized_code")
        tx_code_from_request = req_args.get("tx_code")

        if not pre_authorized_code_from_request:
            return make_response(
                jsonify(
                    {
                        "error": "invalid_request",
                        "error_description": "missing pre-authorized_code",
                    }
                ),
                400,
            )

        if not tx_code_from_request:
            return make_response(
                jsonify({"error": "invalid_request", "error_description": "missing tx_code"}),
                400,
            )

        current_request = request_manager.get_request_by_preauth_code_ref(
            pre_authorized_code_from_request
        )

        if (
            current_request is None
            or current_request.pre_authorized_code_ref != pre_authorized_code_from_request
            or request_manager.preauth_code_expired(current_request)
            or _other_frontend(current_request)
        ):
            error_message = {
                "error": "invalid_grant",
                "error_description": "invalid or expired pre-authorized_code",
            }
            return make_response(jsonify(error_message), 400)

        session_id = current_request.session_id

        # Compared and counted in one step: concurrent guesses cannot exceed the limit.
        tx_code_check = request_manager.check_tx_code(current_request, tx_code_from_request)
        if tx_code_check != "ok":
            error_message = {
                "error": "invalid_grant",
                "error_description": {
                    "invalid": "invalid or expired pre-authorized_code",
                    "revoked": "pre-authorized_code revoked after too many attempts",
                }.get(tx_code_check, "invalid tx_code"),
            }
            return make_response(jsonify(error_message), 400)

        # Construct payload for the internal authorization_code flow
        internal_payload = {
            "grant_type": "authorization_code",
            "code": current_request.pre_authorized_code,
            "redirect_uri": "preauth",  # This should be a consistent value for internal use
            "client_id": "eudiw-abca",
            "state": "vFs5DfvJqoyHj7_dZs2JbdklePg6pMLsUHHmVIfobRw",
        }

        # Make an internal request to the actual OIDC token endpoint via service_endpoint
        # We're simulating calling the OIDC provider's token endpoint directly
        # with the "authorization_code" grant type.
        # The code belongs to the internal pre-authorized client, not to the
        # wallet's client_id: its wallet attestation is still fully verified.
        response_obj = service_endpoint(
            current_app.server.get_endpoint("token"),
            get_args=internal_payload,
            parse_kwargs={"skip_client_id_check": True},
        )

        response_data = response_obj.get_data()

        if response_obj.status_code != 200:
            # The endpoint's own response: a JSON error keeps its Content-Type.
            return response_obj

        response_json = json.loads(response_data)  # Ensure it's JSON from get_data()

        request_manager.revoke_preauth_code(current_request)
        current_app.logger.info(f", Session ID: {session_id}, Pre-Authorized Token Response issued")

        if "access_token" in response_json:
            request_manager.update_access_token(
                session_id=session_id, access_token=response_json["access_token"]
            )
        if "refresh_token" in response_json:
            request_manager.update_refresh_token(
                session_id=session_id,
                refresh_token=response_json["refresh_token"],
                lifetime_seconds=_refresh_token_lifetime(),
            )
        return jsonify(response_json)  # Return as JSON

    elif grant_type == "refresh_token":
        refresh_token = req_args.get("refresh_token")
        if not refresh_token:
            return make_response(
                jsonify(
                    {"error": "invalid_request", "error_description": "missing refresh_token"}
                ),
                400,
            )

        current_request = request_manager.get_request_by_refresh_token(
            refresh_token=refresh_token
        )

        if current_request is None or _other_frontend(current_request):
            error_message = {
                "error": "invalid_grant",
            }
            return make_response(jsonify(error_message), 400)

        session_id = current_request.session_id

        # Pass the request form data to service_endpoint
        response_obj = service_endpoint(current_app.server.get_endpoint("token"))

        response_data = response_obj.get_data()

        if response_obj.status_code != 200:
            # The endpoint's own response: a JSON error keeps its Content-Type.
            return response_obj

        response_json = json.loads(response_data)

        if "access_token" in response_json:
            request_manager.update_access_token(
                session_id=session_id, access_token=response_json["access_token"]
            )

        if "refresh_token" in response_json:
            request_manager.update_refresh_token(
                session_id=session_id,
                refresh_token=response_json["refresh_token"],
                lifetime_seconds=_refresh_token_lifetime(),
            )

        current_app.logger.info(f", Session ID: {session_id}, Refresh Token Response issued")

        return jsonify(response_json)  # Return as JSON

    else:
        # For any other grant type or if grant_type is missing
        error_message = {
            "error": "unsupported_grant_type",
            "error_description": f"The grant type '{grant_type}' is not supported.",
        }

        current_app.logger.info("Token request with an unsupported grant_type")
        return make_response(jsonify(error_message), 400)


@oidc_op_views.route("/introspection", methods=["POST"])
def introspection_endpoint():
    # Only the issuer backend introspects tokens.
    api_key_error = backend_api_key_error()
    if api_key_error is not None:
        return api_key_error

    response = service_endpoint(current_app.server.get_endpoint("introspection"))
    if response.status_code != 200:
        return response
    # A DPoP-bound token's introspection carries cnf.jkt (RFC 9449 section
    # 6.2), set by idpy-oidc: the issuer backend then requires a proof by that key.
    body = json.loads(response.get_data(as_text=True))
    result = make_response(jsonify(body), 200)
    result.headers["Cache-Control"] = "no-store"
    return result


IGNORE = ["cookie", "user-agent"]


def _client_authn_error(err):
    """400 invalid_client: the client (its wallet attestation) did not authenticate.

    RFC 6749 section 5.2 requires 401, with a WWW-Authenticate header (RFC 9110
    section 15.5.2), only when the client authenticated with the Authorization
    header. A wallet attestation is sent in the OAuth-Client-Attestation headers
    and has no HTTP authentication scheme, so 400 is used.
    """
    return make_response(
        json.dumps({"error": "invalid_client", "error_description": str(err) or "client authentication failed"}),
        400,
        {"Content-Type": "application/json"},
    )


def service_endpoint(endpoint, get_args=None, parse_kwargs=None):
    """Run an idpy-oidc endpoint on the current request.

    :param get_args: request arguments to use instead of the request's own
    :param parse_kwargs: extra arguments for parse_request, set only by this
        server (e.g. skip_client_id_check for the internal pre-authorized call)
    """
    _log = current_app.logger
    parse_kwargs = parse_kwargs or {}
    _log.info('At the "{}" endpoint'.format(endpoint.name))

    http_info = {
        "headers": {
            k: v for k, v in request.headers.items(lower=True) if k not in IGNORE
        },
        "method": request.method,
        "url": request.url,
        # name is not unique
        "cookie": [{"name": k, "value": v} for k, v in request.cookies.items()],
    }
    _log.debug(f"http_info: {redact(http_info)}")

    if request.method == "GET":
        args_for_parsing = get_args if get_args is not None else request.args.to_dict()

        try:
            req_args = endpoint.parse_request(args_for_parsing, http_info=http_info, **parse_kwargs)
        except (ClientAuthenticationError, UnAuthorizedClient) as err:
            _log.error(err)
            return _client_authn_error(err)
        except Exception as err:
            _log.error(err)
            return _oauth_error("invalid_request", str(err))
    else:
        if request.data:
            if isinstance(request.data, str):
                req_args = request.data
            else:
                req_args = request.data.decode()
        else:
            req_args = (
                get_args
                if get_args is not None
                else dict([(k, v) for k, v in request.form.items()])
            )
        try:
            req_args = endpoint.parse_request(req_args, http_info=http_info, **parse_kwargs)
        except (ClientAuthenticationError, UnAuthorizedClient) as err:
            _log.warning(f"Client authentication failed at {endpoint.name}: {err}")
            return _client_authn_error(err)
        except Exception as err:
            _log.error(err)
            return _oauth_error("invalid_request", str(err))

    if isinstance(req_args, ResponseMessage) and "error" in req_args:
        _log.info("Error response: {}".format(redact(req_args)))
        return make_response(req_args.to_json(), 400, {"Content-Type": "application/json"})
    try:
        _log.debug("request: {}".format(redact(req_args)))
        if isinstance(endpoint, Token):
            args = endpoint.process_request(
                AccessTokenRequest(**req_args), http_info=http_info
            )
        else:
            args = endpoint.process_request(req_args, http_info=http_info)
    except VerificationError as ve:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
        _resp = Introspection.response_cls(active=False)
        args = {"response_args": _resp}
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
        return _oauth_error("invalid_request", str(err))

    _log.debug("Response args: {}".format(redact(args)))

    if "redirect_location" in args:
        return redirect(args["redirect_location"])
    if "http_response" in args:
        return make_response(args["http_response"], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@oidc_op_views.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return "bad request!", 400


# Pre-authorized flow: only the issuer backend may mint codes (X-Api-Key).
@oidc_op_views.route("/preauth_generate", methods=["POST"])
def prea_auth():
    api_key_error = backend_api_key_error()
    if api_key_error is not None:
        return api_key_error

    session_id = str(uuid4())
    current_app.logger.info(f"Session ID: {session_id}, Pre-Auth generate")
    # request_data = request.get_json(silent=True)
    """ if not request_data:
        request_data = {} """

    scope = request.form.get("scope")  # request_data.get("scope")
    authorization_details = None  # request_data.get("authorization_details")

    # The frontend whose offer this is: the wallet redeems the code at its issuer.
    frontend_id = request.form.get("frontend_id")
    if not use_frontend(frontend_id):
        return _oauth_error("invalid_request", "frontend_id is missing or unknown")

    client_id = "eudiw-abca"
    redirect_uri = "preauth"
    response_type = "code"

    registration_error, _ = dynamic_registration(
        client_id=client_id, redirect_uri=redirect_uri, internal=True
    )
    if registration_error is not None:
        return registration_error

    authorization_args = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
    }
    if scope:
        authorization_args["scope"] = scope
    if authorization_details:
        authorization_args["authorization_details"] = authorization_details

    try:
        # The pre-authorized code grant has no PKCE: only this internal call
        # may skip it.
        response = service_endpoint(
            current_app.server.get_endpoint("authorization"),
            get_args=authorization_args,
            parse_kwargs={"pre_authorized_code": True},
        )

        # Ensure response is what we expect (e.g., has 'data' attribute if it's a Flask Response object)
        if not hasattr(response, "data"):
            current_app.logger.error(
                "Internal service_endpoint did not return expected response object with 'data'."
            )
            return auth_error_redirect(
                authorization_args.get("redirect_uri"),
                "server_error",
                "invalid_internal_response",
            )

        _jws = response.data.decode("utf-8")

        jws = json.loads(_jws)["jws"]

    except requests.exceptions.RequestException as e:
        current_app.logger.error(
            f"Error making internal request to authorization endpoint: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "internal_service_unavailable",
            client_id=authorization_args.get("client_id"),
            state=authorization_args.get("state"),
        )
    except Exception as e:
        current_app.logger.error(
            f"Unexpected error during authorization processing: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "unhandled_exception",
            client_id=authorization_args.get("client_id"),
            state=authorization_args.get("state"),
        )

    tx_code = 10000 + secrets.randbelow(90000)

    try:
        request_manager.add_request(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            authorization_details=authorization_details,
            session_id=session_id,
            tx_code=tx_code,
        )
        request_manager.update_frontend_id(session_id=session_id, frontend_id=frontend_id)
    except Exception as e:
        current_app.logger.error(f"Error adding request: {e}")
        return jsonify({"error": "Failed to process request"}), 500

    try:
        authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
            "user"
        )

        username = authn_method.verify(username=session_id)

        auth_args = authn_method.unpack_token(jws)

    except:
        current_app.logger.error(
            "Authorization verification: username or jws_token not found"
        )
        if "jws_token" in request.args:
            return authentication_error_redirect(
                jws_token=request.args.get("jws_token"),
                error="invalid_request",
                error_description="Authentication verification Error",
            )
        else:
            return "Internal Server Error", 500
            # return render_template("misc/500.html", error="Authentication verification Error")

    authz_request = AuthorizationRequest().from_urlencoded(auth_args["query"])

    endpoint = current_app.server.get_endpoint("authorization")

    _session_id = endpoint.create_session(
        authz_request,
        username,
        auth_args["authn_class_ref"],
        auth_args["iat"],
        authn_method,
    )

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    code, error = _issued_code(args, f"pre-auth session {username}")
    if error is not None:
        return error

    request_manager.update_pre_authorized_code(
        session_id=username, pre_authorized_code=code
    )

    preauth_code_ref = str(uuid4())

    request_manager.update_pre_authorized_code_ref(
        session_id=username, pre_authorized_code_ref=preauth_code_ref
    )

    response = {
        "preauth_code": preauth_code_ref,
        "session_id": session_id,
        "tx_code": tx_code,
    }
    return jsonify(response)
