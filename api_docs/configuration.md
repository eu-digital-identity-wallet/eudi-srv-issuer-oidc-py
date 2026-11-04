# Configuration

For configuring your locally installed version of the EUDIW Issuer Authorization Server, you need to change the following configurations.

## 1. Service Configuration

Base configuration for the EUDIW Issuer Authorization server is located in `config.yaml`, where every setting is commented. A JSON file with the same keys also works.

Parameters that should be changed:

- `domain` Public host of the service (`as.eudiw.dev`), with a path if it shares a hostname (`issuer.eudiw.dev/oidc`); `op.server_info.issuer` is `https://{domain}`
- `port` Port number on which the service is running
- `frontends` Ids of the issuer frontends: every key of the backend's `frontend.frontends_config`. A frontend missing here has no metadata at the issuer its `authorization_servers` names, and its offers are refused.
- `backend_api_key` Key the issuer backend sends in the `X-Api-Key` header to call `/preauth_generate`. It must match `authorization_server.api_key` in the backend configuration. The endpoint answers 503 while it is unset or still `change-me`.

- `trust_validator_url` WIA trust validator URL. Source code available at [eudi-srv-trust-validator](https://github.com/eu-digital-identity-wallet/eudi-srv-trust-validator)
- `status_validator_url` endpoint URL for checking revocation/validity status of Referenced Tokens against a Token Status List. Source code available at [eudi-srv-status-validator-py](https://github.com/eu-digital-identity-wallet/eudi-srv-status-validator-py)
- `status_validation_context` Verification context sent to the status validator for the status list in the WIA's `client_status`. Defaults to `WalletOrKeyStorageStatus`.
- `trusted_attesters_path` WIA trust validation by pem certificate files path

With `trust_validator_url` set, the trust validator alone decides and `trusted_attesters_path` is not used; an unreachable validator fails the request.

### OpenID4VCI options

OpenID4VCI 1.0 RECOMMENDS these features but does not require them. They are on by default; switch one off only to test wallets that do not support it. A feature that is switched off but used anyway is still fully checked (for example a wallet attestation that is sent is verified, and a `plain` PKCE challenge is refused).

| Setting | Default | When `false` |
|---|---|---|
| `require_pushed_authorization_requests` | `true` | Plain `/authorization` requests are accepted (the redirect URI is still checked). |
| `op.server_info.add_ons.pkce.kwargs.essential` | `true` | Requests without `code_challenge` are accepted. `code_challenge_methods` lists the accepted methods (`S256`). |
| `require_dpop` | `true` | `/token` issues bearer tokens to requests without a DPoP proof. |
| `require_wallet_attestation` | `true` | Wallets may also authenticate as public clients at PAR and `/token`. |

The metadata reports the values in force (`require_pushed_authorization_requests`, `code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`, `dpop_signing_alg_values_supported`, `pre-authorized_grant_anonymous_access_supported`).

### Issuers

The server is the authorization server of every frontend in `frontends`. Each has its own issuer, `<op.server_info.issuer>/<frontend id>`, published by the issuer backend in that frontend's `authorization_servers`. With `issuer: https://as.eudiw.dev` and frontend `fe1`:

| What | URL |
|---|---|
| Issuer | `https://as.eudiw.dev/fe1` |
| Pushed authorization, authorization, token | `https://as.eudiw.dev/fe1/{pushed_authorization,authorization,token}` |
| Metadata (RFC 8414) | `https://as.eudiw.dev/.well-known/oauth-authorization-server/fe1` |
| Metadata (also served) | `https://as.eudiw.dev/.well-known/openid-configuration/fe1`, `https://as.eudiw.dev/fe1/.well-known/{oauth-authorization-server,openid-configuration}` |
| Shared: introspection, `preauth_generate`, `verify/user`, keys | `https://as.eudiw.dev/{introspection,preauth_generate,verify/user,static/jwks.json}` |

A trailing slash in the issuer is ignored. An issuer with a path (`https://issuer.eudiw.dev/oidc`) works the same way: every route is served under that path (`/oidc/fe1/token`), and the RFC 8414 metadata is at `/.well-known/oauth-authorization-server/oidc/fe1`. The authorization response `iss` (RFC 9207), the token `iss`, the expected wallet attestation PoP `aud` and the DPoP `htu` (RFC 9449) are the frontend's issuer and its endpoints. A request URI, code or refresh token is only accepted at the issuer of the frontend it was issued for.

The listen address of the built-in server is `webserver.host` (`0.0.0.0` in containers, `127.0.0.1` for a local run).

## 2. Session hand-off to the issuer backend

After an authorization request the server redirects the browser to `authorization_redirect_url` (the backend `/auth_choice`). Besides `token`, `session_id`, `scope` and `authorization_details`, the redirect carries `session_token`: an ES256 JWT signed with the server key (published at `/static/jwks.json`), `aud` `eudiw-issuer-backend`, valid for 5 minutes, with the claims `session_id`, `scope`, `authorization_details` and `frontend_id`. The backend only trusts these signed claims.

A wallet-supplied `issuer_state` is stored with the request but never used as the session id. `/verify/user` only completes an authorization when `username` is the session created for the authorization request in `token`.

Pre-authorized codes can be redeemed for 10 minutes and once only; five wrong `tx_code` attempts revoke the code.
