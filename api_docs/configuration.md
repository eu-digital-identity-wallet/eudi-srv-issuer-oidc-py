# Configuration

For configuring your locally installed version of the EUDIW Issuer Authorization Server, you need to change the following configurations.

## 1. Service Configuration

Base configuration for the EUDIW Issuer Authorization server is located in ```config.json``.

Parameters that should be changed:

- `domain` (Base url of the service)
- `port` Port number on which the service is running
- `allowed_htu` List of allowed DPoP htu

- `trust_validator_url` WIA trust validator URL. Source code available at [eudi-srv-trust-validator](https://github.com/eu-digital-identity-wallet/eudi-srv-trust-validator)
- `status_validator_url` endpoint URL for checking revocation/validity status of Referenced Tokens against a Token Status List. Source code available at [eudi-srv-status-validator-py](https://github.com/eu-digital-identity-wallet/eudi-srv-status-validator-py)
- `trusted_attesters_path` WIA trust validation by pem certificate files path

trust_validator_url and trusted_attesters_path should not be used at the same time.