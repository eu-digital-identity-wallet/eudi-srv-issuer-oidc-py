#!/usr/bin/env python3
import argparse
import json
import logging
import os

from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.ssl_context import create_context

try:
    from . import housekeeping
    from .application import oidc_provider_init_app
    from .security import configure_client_authentication, configure_frontends, init_rate_limits, trust_proxies
except (ModuleNotFoundError, ImportError):
    import housekeeping
    from application import oidc_provider_init_app
    from security import configure_client_authentication, configure_frontends, init_rate_limits, trust_proxies

dir_path = os.path.dirname(os.path.realpath(__file__))

logger = logging.getLogger(__name__)


# class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
#     """
#     We subclass this class so that we can gain access to the connection
#     property. self.connection is the underlying client socket. When a TLS
#     connection is established, the underlying socket is an instance of
#     SSLSocket, which in turn exposes the getpeercert() method.
#
#     The output from that method is what we want to make available elsewhere
#     in the application.
#     """
#
#     def make_environ(self):
#         """
#         The superclass method develops the environ hash that eventually
#         forms part of the Flask request object.
#
#         We allow the superclass method to run first, then we insert the
#         peer certificate into the hash. That exposes it to us later in
#         the request variable that Flask provides
#         """
#         environ = super(PeerCertWSGIRequestHandler, self).make_environ()
#         x509_binary = self.connection.getpeercert(True)
#         if x509_binary:
#             x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
#             environ['peercert'] = x509
#         else:
#             logger.warning('No peer certificate')
#             environ['peercert'] = ''
#         return environ


def create_app(config_file: str):
    """Builds the authorization server from a configuration file.

    Args:
        config_file: Path of the configuration (YAML or JSON).

    Returns:
        ``(app, config)``: the Flask application, ready to serve, and the
        loaded configuration (``config.web_conf`` holds the web server
        settings).
    """
    config = create_from_config_file(
        Configuration,
        entity_conf=[
            {"class": OPConfiguration, "attr": "op", "path": ["op", "server_info"]}
        ],
        filename=config_file,
        base_path=dir_path,
    )
    # Frontend issuers are <issuer>/<frontend id>: no double slash, as the
    # backend strips its authorization_server.base_url too.
    config.op["issuer"] = str(config.op["issuer"]).rstrip("/")
    app = oidc_provider_init_app(config.op, "oidc_op")
    app.logger = config.logger

    app.authorization_redirect_url = config.authorization_redirect_url
    # The issuer frontends: each has its own issuer, <issuer>/<frontend id>.
    configure_frontends(app, getattr(config, "frontends", None))
    # Shared with the issuer backend; protects /preauth_generate.
    app.backend_api_key = getattr(config, "backend_api_key", None)
    rate_limiting = getattr(config, "rate_limiting", None) or {}
    trust_proxies(app, int(rate_limiting.get("trusted_proxies", 0) or 0))
    init_rate_limits(app, rate_limiting)
    # Non-pushed authorization requests are refused unless this is false.
    app.require_pushed_authorization_requests = getattr(
        config, "require_pushed_authorization_requests", True
    ) is not False
    # Tokens without a DPoP proof are refused unless this is false.
    app.require_dpop = getattr(config, "require_dpop", True) is not False
    # Wallet attestation (WIA) at PAR and /token, unless this is false.
    app.require_wallet_attestation = getattr(config, "require_wallet_attestation", True) is not False
    configure_client_authentication(app, app.require_wallet_attestation)
    # Minutes between two removals of expired in-memory entries.
    app.cleanup_interval = getattr(config, "cleanup_interval", None) or housekeeping.DEFAULT_CLEANUP_INTERVAL
    return app, config


def main(config_file, args):
    logging.basicConfig(level=logging.INFO)
    app, config = create_app(config_file)

    web_conf = config.web_conf

    context = create_context(dir_path, web_conf)

    if args.display:
        print(json.dumps(app.server.get_context().provider_info, indent=4, sort_keys=True))
        exit(0)

    kwargs = {}
    """ if context:
        kwargs["ssl_context"] = context """
        # kwargs["request_handler"] = PeerCertWSGIRequestHandler

    housekeeping.start(app, app.cleanup_interval)

    # Containers need every interface; set webserver.host to 127.0.0.1 to
    # keep a bare-metal or development server off the network.
    app.run(
        host=web_conf.get("host", "0.0.0.0"),
        port=web_conf["port"],
        debug=web_conf["debug"],
        **kwargs
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="display", action="store_true")
    parser.add_argument("-t", dest="tls", action="store_true")
    parser.add_argument("-k", dest="insecure", action="store_true")
    parser.add_argument(dest="config")
    args = parser.parse_args()
    main(args.config, args)
