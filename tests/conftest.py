"""Builds the authorization server from config.yaml with throw-away keys."""

import base64
import copy
import datetime
import json
import os
import sys
import time
import uuid

import jwt as pyjwt
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BACKEND_API_KEY = "k" * 40
WALLET_CLIENT_ID = "wallet-test"
#: Path of the test issuer (https://issuer.eudiw.dev/oidc): every route is under it.
#: config.yaml has none (https://as.eudiw.dev); tests/test_frontends.py covers that.
PREFIX = "/oidc"
#: Frontends of the test server; each has the issuer <issuer>/<frontend id>.
FRONTEND_ID = "fe"
OTHER_FRONTEND_ID = "fe2"
#: Path of FRONTEND_ID's issuer: its PAR, authorization, token and metadata.
FE = f"{PREFIX}/{FRONTEND_ID}"


def _self_signed(key, cn):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


# Test wallet provider (a trusted attester) and the wallet instance key it attests
WALLET_PROVIDER_KEY = ec.generate_private_key(ec.SECP256R1())
WALLET_PROVIDER_CERT = _self_signed(WALLET_PROVIDER_KEY, "Test Wallet Provider")
WALLET_INSTANCE_KEY = ec.generate_private_key(ec.SECP256R1())


def make_wia_headers(aud, client_id=WALLET_CLIENT_ID, pop_aud=None, signer=None):
    """OAuth-Client-Attestation (WIA) and -PoP headers from the test wallet."""
    now = int(time.time())
    instance_jwk = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(WALLET_INSTANCE_KEY.public_key()))
    x5c = [base64.b64encode(WALLET_PROVIDER_CERT.public_bytes(serialization.Encoding.DER)).decode()]
    wia = pyjwt.encode(
        {
            "iss": "https://wallet-provider.test",
            "sub": client_id,
            "iat": now,
            "exp": now + 3600,
            "cnf": {"jwk": instance_jwk},
            "wallet_name": "Test wallet",
            "wallet_version": "1",
            "wallet_solution_certification_information": "test",
            "client_status": {"status": {"status_list": {"idx": 1, "uri": "https://status.test/1"}}, "exp": now + 86400},
        },
        signer or WALLET_PROVIDER_KEY,
        algorithm="ES256",
        headers={"typ": "oauth-client-attestation+jwt", "x5c": x5c},
    )
    pop = pyjwt.encode(
        {"iss": client_id, "aud": pop_aud or aud, "jti": str(uuid.uuid4()), "iat": now},
        WALLET_INSTANCE_KEY,
        algorithm="ES256",
        headers={"typ": "oauth-client-attestation-pop+jwt"},
    )
    return {"OAuth-Client-Attestation": wia, "OAuth-Client-Attestation-PoP": pop}


def _test_config(tmp_path):
    with open(os.path.join(ROOT, "config.yaml")) as f:
        config = yaml.safe_load(f)
    config = copy.deepcopy(config)
    config["logging"] = {"version": 1, "disable_existing_loggers": False, "root": {"level": "WARNING"}}
    server_info = config["op"]["server_info"]
    # Generated per test run; nothing is written into the repository.
    server_info["keys"].update(
        {
            "private_path": str(tmp_path / "jwks.json"),
            "public_path": str(tmp_path / "public_jwks.json"),
            "read_only": False,
        }
    )
    server_info["cookie_handler"]["kwargs"]["keys"]["private_path"] = str(tmp_path / "cookie_jwks.json")
    token_args = server_info["token_handler_args"]
    token_args.pop("jwks_file", None)
    token_args["jwks_def"] = {
        "private_path": str(tmp_path / "token_jwks.json"),
        "key_defs": [
            {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
            {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
        ],
        "read_only": False,
    }
    # Wallet attestations are checked against a local trusted attester, no
    # trust or status validator service.
    attesters = tmp_path / "attesters"
    attesters.mkdir()
    (attesters / "wallet_provider.pem").write_bytes(WALLET_PROVIDER_CERT.public_bytes(serialization.Encoding.PEM))
    token_kwargs = server_info["endpoint"]["token"]["kwargs"]
    token_kwargs["trusted_attesters_path"] = str(attesters)
    token_kwargs.pop("trust_validator_url", None)
    token_kwargs.pop("status_validator_url", None)
    config["backend_api_key"] = BACKEND_API_KEY
    config["frontends"] = [FRONTEND_ID, OTHER_FRONTEND_ID]
    config["domain"] = "issuer.eudiw.dev" + PREFIX
    config["authorization_redirect_url"] = "https://backend.test/auth_choice"
    # Tests that need rate limits apply them themselves (init_rate_limits).
    config["rate_limiting"] = {"enabled": False}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return str(path)


@pytest.fixture
def app(tmp_path):
    """The server as server.main builds it (server.create_app), from the test configuration."""
    import application
    import server

    application.request_manager.__init__(default_expiry_minutes=1450)
    app, _ = server.create_app(_test_config(tmp_path))
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def published_jwks(app):
    """A JWKS file in static/ (the real one is generated at start-up and not in git)."""
    name = f"test-{uuid.uuid4().hex}.json"
    path = os.path.join(app.root_path, "static", name)
    with open(path, "w") as f:
        json.dump({"keys": []}, f)
    yield name
    os.remove(path)


@pytest.fixture
def wia(app):
    """wia(client_id=..., **kw) -> WIA + PoP headers for FRONTEND_ID's issuer."""
    issuer = f"{app.server.get_context().issuer}/{FRONTEND_ID}"
    return lambda client_id=WALLET_CLIENT_ID, **kw: make_wia_headers(issuer, client_id, **kw)
