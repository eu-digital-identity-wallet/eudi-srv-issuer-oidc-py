# Installation

## 1. Python

The Authorization Server was tested with

+ Python version 3.9.2

and should only be used with Python 3.9 or 3.10.

If you don't have it installed, please download it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. Flask

The Authorization Server was tested with

+ Flask v. 2.3

and should only be used with Flask v. 2.3 or higher.

To install [Flask](https://flask.palletsprojects.com/en/2.3.x/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/2.3.x/installation/).


## 3. How to run the Authorization Server?

1. Clone the EUDIW Authorization Server repository:

    ```shell
    git clone git@github.com:eu-digital-identity-wallet/eudi-srv-issuer-oidc-py.git
    ```

2. Activate the environment:

   Linux/macOS

    ```shell
    . .venv/bin/activate
    ```

    Windows

    ```shell
    . .venv\Scripts\Activate
    ```

3. Install or upgrade _pip_

    ```shell
    python -m pip install --upgrade pip
    ```

4. Install Flask and other dependencies in virtual environment

    ```shell
    pip install -r requirements.txt
    ```

5. Service Configuration

   - Configure the service according to [documentation](api_docs/configuration.md)  
   ```
6. Install Issuer Back-End
    - Install the service according to [Issuer Back End](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/blob/main/install.md)

7. Install Issuer Front-End
    - Install the service according to [Issuer Front End](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-frontend-eudiw-py/blob/main/install.md)


8. Run the EUDIW Authorization Server

    On the root directory of the clone repository, insert one of the following command lines to run the EUDIW Authorization Server.

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000>)

    ```
    ./run.sh
    ```


## 5. Make your local EUDIW AUthorization Server available on the Internet (optional)

If you want to make your local EUDIW AUthorization Server  available on the Internet, we recommend to use NGINX reverse proxy and certbot (to generate an HTTPS certificate).

### 5.1 Install and configure NGINX

1. Follow the installation guide in https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/

2. Configure your local EUDIW Issuer. For example, use the following Nginx configuration file (for a Linux installation):

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

# Provider backend
    location / {
        # The proxy_pass directive assumes that your local EUDIW Issuer is running at http://127.0.0.1:5000/. 
        # If not, please adjust it accordingly.
        proxy_pass                              http://127.0.0.1:5000/;
        proxy_set_header Host                   $http_host;
        proxy_set_header X-Real-IP              $remote_addr;
        proxy_set_header X-Forwarded-For        $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto      $scheme;
    }
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

    * **Update variables:** Edit the newly created `config.json` file with your specific settings.
        * *Reference example:* [config.json example](./config.json)


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