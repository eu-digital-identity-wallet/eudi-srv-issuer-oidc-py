# Changelog

## [0.9.5]

_5 Aug 2026_

### Changed
- Updated implementation to align with EUDI TS3 v1.5 specification.

## [0.9.6]

_06 Oct 2026_

### Added
- `session_token` in the redirect to the issuer backend: an ES256 JWT with the session id, scope and authorization details, so the backend no longer trusts query parameters.
- `backend_api_key` configuration: `/preauth_generate` and `/introspection` require it in the `X-Api-Key` header; anyone could mint pre-authorized codes.
- DPoP binding: proofs at `/token` are checked (signature, `htm`, `htu`, `iat`, single-use `jti`), the access token is bound to the proof key, and `/introspection` returns `cnf.jkt`.
- Per-client rate limits (`rate_limiting`, Flask-Limiter) on `/token`, `/pushed_authorization`, `/authorization` and `/verify/user` (not on the backend-only `/preauth_generate` and `/introspection`, where one address serves every user).
- Test suite (`tests/`) and a CI workflow running it.

### Changed
- A wallet-supplied `issuer_state` is no longer used as the session id, which let a client choose or overwrite a session.
- `/verify/user` only completes the session created for the authorization request in its token.
- Pre-authorized codes expire after 10 minutes, can be redeemed once, and are revoked after 5 wrong `tx_code` attempts; the `tx_code` is generated with `secrets`.
- Keys are no longer committed: they are generated on first start into `private/` (mount a volume to keep them). `httpc_params.verify` is now `true` and `debug` is off.
- HMAC algorithms removed from `dpop_signing_alg_values_supported`.
- The discovery document no longer advertises logout support that is not implemented, and lists the pre-authorized code grant.
- Session cookies are `Secure` and `HttpOnly`.
- Requirements use the niscy-eudiw idpy-oidc fork pinned to a commit.
- The Docker image runs as an unprivileged user (UID 10001) and only copies the application files.
- CI: SonarCloud runs on `pull_request` instead of `pull_request_target` and actions are pinned to commit SHAs.
- Removed the `/jwt_token` test route.
- A Wallet Instance Attestation is required at `/pushed_authorization` and `/token`: `client_authn_method` is only `wallet_attestation`. The `public` method let any client skip the WIA (trust, revocation and proof-of-possession checks) by not sending it.
- The internal pre-authorized code call skips the WIA `sub` / `client_id` comparison through a server-side flag; the fork no longer skips it for any request with `redirect_uri=preauth`.

### Fixed
- Unknown authorization or pre-authorized codes and non-numeric `tx_code` values returned 500 instead of 400.
- Codes, tokens, tx_codes and DPoP / authorization headers are redacted from logs, and `request_manager` logs through `logging` instead of `print`.
- `check_session_iframe` compared the client id with the whole client database.
- A pushed authorization request whose client authentication (e.g. the WIA) fails returns that error instead of a 500.
- Client authentication failures at `/token` and `/pushed_authorization` return 401 `invalid_client` instead of 400.

## [Unreleased]

### Added
- `cleanup_interval` (minutes, default 60): `housekeeping.py` removes expired authorization requests, tokens and pushed requests in the background.
- `require_wallet_attestation` (default `true`): `false` lets wallets authenticate as public clients; a sent attestation is still verified.
- `par_allowed_htu` (DPoP add-on): the public `/pushed_authorization` URLs a DPoP proof may name.
- `pop_allowed_aud` (token endpoint `kwargs`): the frontends' issuer identifiers, accepted as wallet attestation PoP `aud`.
- `status_validation_context` (default `WalletOrKeyStorageStatus`, was `PIDStatus`): the status validator context for the WIA `client_status`.
- `rate_limiting.forwarders`: peers whose requests are limited per `X-Forwarded-For` address (the frontend).
- `webserver.host` (default `0.0.0.0`); it was hard-coded.

### Changed
- Secure defaults, each of which can be switched off for testing:
  - PKCE is required, `S256` only (`add_ons.pkce.kwargs.essential`); the misspelt option made it optional.
  - Authorization requests must be pushed (`require_pushed_authorization_requests`, HAIP).
  - `/token` requires a DPoP proof (`require_dpop`).
  - `/.well-known/openid-configuration` reports the values in force.
- DPoP is validated and bound by the idpy-oidc DPoP add-on only; `dpop.py` is removed.
- `/authorization` passes only `client_id` and `request_uri` to the authorization endpoint (RFC 9126 section 4).
- Redirect URIs must be `https`, loopback `http` or a private-use scheme (not `javascript`, `data`, `vbscript`, `file`, `blob`, `about`), without a fragment.
- Error responses follow RFC 6749, RFC 9126 and RFC 9396: JSON with `error_description`, `201` from PAR, `invalid_request_uri`, `invalid_authorization_details`, `405` for wrong methods, `no-store` on token responses.
- Wallet attestation failures answer `400 invalid_client` (RFC 6749 section 5.2).
- Refresh tokens, issuance usage rules and their sessions last one week.
- `server.create_app(config_file)` builds the application, for `main()` and the tests. Coverage 70% -> 98%.
- Dependencies are installed from `requirements.txt`.
- `pyjwt` 2.15.1 (PYSEC-2026-178, PYSEC-2026-4140 to 4152, PYSEC-2026-4183).
- `pipeline.yml` runs on `main` and `branch-*` instead of `dev`, `preprod` and `main`.
- GitHub Actions: Docker actions pinned to commit SHAs; read-only token permissions per job.
- The Docker build no longer upgrades pip; CI installs semgrep from wheels only.
- Removed `yaml_to_json.py`.
- SonarCloud: `views.py` reads the DPoP header with `.get()`; the CSRF hotspot (S4502) is documented and marked `# NOSONAR`.

### Fixed
- A code from a request with `dpop_jkt` could be redeemed with any key's DPoP proof (RFC 9449 section 10).
- Concurrent token requests with one code could each get tokens.
- Concurrent wrong `tx_code` guesses could exceed the limit of 5.
- Concurrent client registrations could fail with "No registered redirect_uri" or lose a redirect URI.
- Expired authorization requests were not cleaned during the first minute after boot.
- Error redirects from `/verify/user` lacked `state` (RFC 6749 4.1.2.1) and broke a `redirect_uri` with a query.
- `python3 server.py -d <config>` crashed.
- `auth_error_redirect` used the request's `redirect_uri` instead of the registered one (SonarCloud open redirect).
- Logs contained the client's `client_id`, `request_uri` and token request form (SonarCloud log injection).
