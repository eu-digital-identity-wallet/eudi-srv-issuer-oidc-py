# Installation

## 1. Python

The EUDIW Issuer was tested with

+ Python version 3.13

and should only be used with Python 3.10+.

If you don't have it installed, please download it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. Flask

The EUDIW Issuer was tested with

+ Flask v. 3.1

and should only be used with Flask v. 3.1 or higher.

To install [Flask](https://flask.palletsprojects.com/en/stable/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/stable/installation/).

## 3. How to run the Authorization Server?

1. Clone the EUDIW Authorization Server repository:

    ```shell
    git clone git@github.com:eu-digital-identity-wallet/eudi-srv-issuer-oidc-py.git
    ```

2. Create a `.venv` folder within the cloned repository:

    ```shell
    cd eudi-srv-issuer-oidc-py
    python3 -m venv .venv
    ```

3. Activate the environment:

   Linux/macOS

    ```shell
    . .venv/bin/activate
    ```

    Windows

    ```shell
    . .venv\Scripts\Activate
    ```

4. Install or upgrade _pip_

    ```shell
    python -m pip install --upgrade pip
    ```

5. Install Flask and other dependencies in virtual environment

    ```shell
    pip install -r requirements.txt
    ```

    Use `requirements-dev.txt` instead of `requirements.txt` to run the tests.

6. Service Configuration

   - Configure the service according to [documentation](api_docs/configuration.md)  
   
7. Install Issuer Back-End
    - Install the service according to [Issuer Back End](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/blob/main/install.md)

8. Install Issuer Front-End
    - Install the service according to [Issuer Front End](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-frontend-eudiw-py/blob/main/install.md)


9. Run the EUDIW Authorization Server

    On the root directory of the clone repository, insert one of the following command lines to run the EUDIW Authorization Server.

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000>)

    ```
    ./run.sh
    ```


## 5. Make your local EUDIW Authorization Server available on the Internet (optional)

The server answers at its issuer, `op.server_info.issuer` (e.g. `https://as.eudiw.dev`), including the RFC 8414 metadata at the host root (`/.well-known/oauth-authorization-server/<frontend id>`). An issuer with a path (`https://issuer.eudiw.dev/oidc`) has every route under that path. See [Issuers](api_docs/configuration.md#issuers). A reverse proxy is optional:

* **Own hostname, no proxy** (e.g. Docker on Azure Container Apps or App Service): set `domain` to the public host (`as.eudiw.dev` gives issuers `https://as.eudiw.dev/<frontend id>`). The platform ingress terminates TLS; `rate_limiting.trusted_proxies: 1` trusts its `X-Forwarded-For`, `-Proto` and `-Host`.
* **Hostname shared with other services** (e.g. `issuer.eudiw.dev/oidc` next to the issuer frontend): a path router (nginx, Azure Application Gateway or Front Door) must send `/oidc/` and the host-root `/.well-known/oauth-authorization-server/oidc/` and `/.well-known/openid-configuration/oidc/` to this server, without stripping the path. An nginx example follows.

### 5.1 Install and configure NGINX

1. Follow the installation guide in https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/

2. Configure your local EUDIW Authorization Server. For example, use the following Nginx configuration file (for a Linux installation), with `domain: FQDN/oidc`:

```nginx
server {
    server_name FQDN; # Change to the FQDN you want to use

    listen 80;
    access_log /var/log/nginx/issuer.eudiw.access.log;
    error_log /var/log/nginx/issuer.eudiw.error.log;
    root /var/www/html;

# Recommended
    proxy_busy_buffers_size   512k;
    proxy_buffers   4 512k;
    proxy_buffer_size   256k;

# Authorization server: its routes and its RFC 8414 metadata. The proxy_pass
# directives assume the server runs at http://127.0.0.1:5000; no URI part, so
# the path is passed unchanged.
    location /oidc/ {
        proxy_pass                              http://127.0.0.1:5000;
        proxy_set_header Host                   $http_host;
        proxy_set_header X-Real-IP              $remote_addr;
        proxy_set_header X-Forwarded-For        $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto      $scheme;
    }
    location ~ ^/\.well-known/(oauth-authorization-server|openid-configuration)/oidc/ {
        proxy_pass                              http://127.0.0.1:5000;
        proxy_set_header Host                   $http_host;
        proxy_set_header X-Forwarded-For        $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto      $scheme;
    }
# Other services on this host (e.g. the issuer frontend) go in further locations.
}
```

3. Restart the Nginx server


### 5.2 Install and run certbot to gef a free HTTPS certificate

1. Follow the installation guide in https://certbot.eff.org

2. Run `certbot` to get a free HTTPS certificate. The `certbot` will also configure the EUDIW Issuer Nginx configuration file with the HTTPS certificate.

3. Restart the Nginx server and goto `https:\\FQDN\` (FQDN configured in the Nginx configuration file)


## 6. Docker

This guide provides step-by-step instructions for deploying the **EUDIW Issuer Authorization** service using **Docker Compose v2**.

1. Install docker

    Ensure you have Docker installed on your system. Follow the **official installation instructions** for your operating system:
    [https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)


2. Configure Docker Compose

    The service's container orchestration is managed by the `docker-compose.yml` file.

    * **Customize the configuration:** Review and modify the local `docker-compose.yml` file to align with your specific deployment requirements (e.g., exposed ports, service names, volumes).
    * *Reference file:* [docker-compose.yml](./docker-compose.yml)

3. Set Up configuration file

    Service parameters and sensitive settings are managed through a configuration file.

    * **Create the configuration file:** We recommend copying the example file to create your local configuration.

    * **Update variables:** Edit the newly created `config.yaml` file with your specific settings; every setting is commented.
        * *Reference example:* [config.yaml example](./config.yaml)
        * A JSON file with the same keys still works (`server.py` reads `.json` or `.yaml` by extension); the Docker image reads `/etc/issuer_config/authorization_config.yaml`.


4. Pull the Docker Image

    ```
    docker compose pull
    ```

5. Run the 

    Start the EUDIW Issuer backend in detached mode (runs in the background):

    ```
    docker compose up -d
    ```

6. Check Logs

    To confirm the service is running correctly and to monitor its output in real-time for troubleshooting, use the following command:
    ```
    docker compose logs -f
    ```

7. Deploy Related Services

To complete the full EUDIW ecosystem, you will also need to deploy the associated Front-end and Back-end components if you haven't already.

* **Front-end Installation:** Follow the guide to install the web issuing front-end component using Docker.
    * [Front-end Deployment Guide](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-frontend-eudiw-py/blob/main/install.md#6-docker)

* **Back-end Installation:** Follow the guide to install the back-end component using Docker.
    * [Back-end Deployment Guide](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/blob/main/install.md#6-docker)