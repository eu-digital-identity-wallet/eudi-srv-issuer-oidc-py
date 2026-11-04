import os
import threading
from urllib.parse import urlparse

from flask.app import Flask

from idpyoidc.server import Server

folder = os.path.dirname(os.path.realpath(__file__))

from request_manager import RequestManager

request_manager = RequestManager(default_expiry_minutes=1450)


def init_oidc_op(app):
    _op_config = app.srv_config

    server = Server(_op_config, cwd=folder)

    for endp in server.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split("/")
        if _vpath[0] == "":
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    return server


def oidc_provider_init_app(op_config, name=None, **kwargs):
    name = name or __name__
    # No CSRF tokens, by design (SonarCloud S4502 reviewed as safe): no endpoint
    # acts on a browser's ambient credentials. PAR, /token and /introspection
    # are APIs authenticated by wallet attestation, DPoP or the backend's API
    # key header; /authorization only starts a flow for a request_uri the
    # wallet pushed; /verify/user needs a single-use token signed for that
    # session by the issuer backend. Reviewed: suppressed below (NOSONAR).
    app = Flask(name, static_folder=None, **kwargs)  # NOSONAR - CSRF not applicable, see above
    app.srv_config = op_config

    try:
        from . import views
    except ImportError:
        import views

    # Initialize the oidc_provider after views to be able to set correct urls
    app.server = init_oidc_op(app)

    # The routes live under the path of the issuer (https://host/oidc -> /oidc),
    # so no reverse proxy has to strip it; the RFC 8414 discovery URLs sit at
    # the host root.
    prefix = urlparse(app.server.get_context().issuer).path.rstrip("/")
    app.register_blueprint(views.oidc_op_views, url_prefix=prefix or None)
    views.register_well_known(app, prefix)
    app.teardown_request(views.reset_frontend)

    return app
