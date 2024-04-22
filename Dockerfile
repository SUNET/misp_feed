FROM debian:bookworm-20240408-slim@sha256:3d5df92588469a4c503adbead0e4129ef3f88e223954011c2169073897547cac

MAINTAINER pettai@sunet.se

EXPOSE 8008/tcp

# Metadata
LABEL version="1.04"
LABEL description="misp-feed-service server"

# Set work dir
WORKDIR /app

# Copy the requirement.txt file needed to install deps
COPY ./requirements.txt /app/requirements.txt

# Install deps
RUN apt-get update \
    && apt-get install -y \
    python3-pip \
    python3 \
    build-essential \
    dnsutils \
    python3-venv \
    && python3 -m venv .venv && . .venv/bin/activate \
    && pip3 install --require-hashes -r requirements.txt \
    && apt-get remove -y \
    python3-pip \
    && apt-get autoremove -y

# Remove setuid and setgid
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true

# Add user and add to softhsm group
RUN useradd misp-feed -u 1500 -s /usr/sbin/nologin

RUN mkdir -p .venv/lib/python3.11/site-packages/pymisp/data/misp-objects/objects/sunet-c2
COPY definition.json .venv/lib/python3.11/site-packages/pymisp/data/misp-objects/objects/sunet-c2/definition.json

# Copy files
COPY ./src /app/src
# COPY ./tests /app/tests
# COPY ./data/trusted_keys /app/trusted_keys
# COPY ./containers/healthcheck.sh /app/healthcheck.sh
# COPY ./containers/healthcheck.py /app/healthcheck.py
COPY ./logging.json /app/logging.json


# Run as user
USER misp-feed

# Add healthcheck
# HEALTHCHECK --interval=120s --timeout=15s --retries=1 --start-period=30s \
#     CMD sh '. .venv/bin/activate && healthcheck.sh' || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'


# CMD sh -c '. .venv/bin/activate && uvicorn src.pkcs11_ca_service.main:app --ssl-keyfile tls_key.key --ssl-certfile tls_certificate.pem --ssl-version 2 --log-config ./logging.json --host 0.0.0.0 --port 8008 --workers 1 --header server:pkcs11_ca'

CMD sh -c '. .venv/bin/activate && uvicorn src.misp_feed_service.main:app --log-config ./logging.json --host 0.0.0.0 --port 8008 --workers 1 --header server:misp_feed'
