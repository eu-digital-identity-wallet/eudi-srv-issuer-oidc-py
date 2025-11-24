# EUDIW Issuer Authorization Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

### Overview

The EUDIW Issuer Authorization Server implements the authorization and token endpoints required for **OpenID for Verifiable Credential Issuance (OIDC4VCI)** within the **European Digital Identity Wallet (EUDIW)** framework.


### OpenId4VCI coverage

This version of the EUDIW Issuer Authorization Server has support for the [OpenId for Verifiable Credential Issuance (Version 1.0)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) protocol with the following coverage:


| Feature                                                   | Coverage                                                        |
|-------------------------------------------------------------------|-----------------------------------------------------------------|
| [Authorization Code flow](api_docs/authorization.md)              | ✅ Support for scoped                                           |
| [Pre-authorized code flow](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-frontend-eudiw-py/blob/main/api_docs/pre-authorized.md)            | ✅                                                              |
| [Token Endpoint](api_docs/token.md)                               | ✅                                                              |
| Pushed authorization request (PAR)                                      | ✅                                                              |
| Wallet authentication                                             | ✅ public client, Wallet client attestations                    |
| Demonstrating Proof of Possession (DPoP)                          | ✅                                                              |
| PKCE                                                              | ✅                                                              |



## :heavy_exclamation_mark: Disclaimer

The released software is a initial development release version:

-   The initial development release is an early endeavor reflecting the efforts of a short timeboxed
    period, and by no means can be considered as the final product.
-   The initial development release may be changed substantially over time, might introduce new
    features but also may change or remove existing ones, potentially breaking compatibility with your
    existing code.
-   The initial development release is limited in functional scope.
-   The initial development release may contain errors or design flaws and other problems that could
    cause system or other failures and data loss.
-   The initial development release has reduced security, privacy, availability, and reliability
    standards relative to future releases. This could make the software slower, less reliable, or more
    vulnerable to attacks than mature software.
-   The initial development release is not yet comprehensively documented.
-   Users of the software must perform sufficient engineering and additional testing in order to
    properly evaluate their application and determine whether any of the open-sourced components is
    suitable for use in that application.
-   We strongly recommend not putting this version of the software into production use.
-   Only the latest version of the software will be supported



## 1. Installation

Pre-requisites:

+ Python v. 3.9 or 3.10
+ Flask v. 2.3 or higher

Click [here](install.md) for detailed installation instructions.

## 3. Frequently Asked Questions

### A. How to make your local Authorization server available on the Internet?

Please see detailed instructions in [install.md](install.md#4-make-your-local-eudiw-issuer-available-on-the-internet-optional).

### B. Can I run the Authorization Server in a Docker container?

Yes. Please see how in [Install Docker](install.md#6-docker).

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.