#!/usr/bin/env bash

set -e

SERVER_TRANSPORT_KEY_OUT="server_transport_key.pem"
SERVER_TRANSPORT_CERT_OUT="server_transport_cert.pem"

SERVER_STORAGE_KEY_OUT="server_storage_key.pem"
SERVER_STORAGE_CERT_OUT="server_storage_cert.pem"

# create transport certificate and key
openssl req -x509 -newkey rsa:4096 \
 -sha256 \
 -days 365 \
 -nodes \
 -keyout "$SERVER_TRANSPORT_KEY_OUT" \
 -out "$SERVER_TRANSPORT_CERT_OUT" \
 -subj "/C=IT/ST=Sardinia/L=Cagliari/O=E2E-chat/OU=Transport/CN=localhost" \
 -addext "subjectAltName=DNS:localhost"

# create storage certificate and key
openssl req -x509 -newkey rsa:4096 \
  -sha256 \
  -days 365 \
  -nodes \
  -keyout "$SERVER_STORAGE_KEY_OUT" \
  -out "$SERVER_STORAGE_CERT_OUT" \
  -subj "/C=US/ST=Sardinia/L=Cagliari/O=E2E-chat/OU=Storage/CN=localhost"

# copy storage certificate to client
cp "$SERVER_STORAGE_CERT_OUT" ../client
cp "$SERVER_TRANSPORT_CERT_OUT" ../client