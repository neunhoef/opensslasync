#!/bin/bash

mkdir -p certificates

# Create a ca key:
openssl genrsa -aes256 -passout pass:abcd1234 -out certificates/ca-key.pem 2048

# Inspect it:
openssl rsa -in certificates/ca-key.pem -text -noout -passin pass:abcd1234

# Create a certificate from it:
openssl req -x509 -new -nodes -extensions v3_ca -key certificates/ca-key.pem -days 1024 -out certificates/ca-root.pem -sha512 -subj "/C=DE/ST=NRW/L=Kerpen/O=Neunhoeffer/OU=Max/CN=Max Neunhoeffer/emailAddress=max@9hoeffer.de/" -passin pass:abcd1234

# Inspect it:
openssl x509 -in certificates/ca-root.pem -text -noout

# Verify it:
openssl verify -CAfile certificates/ca-root.pem certificates/ca-root.pem

# Create server key:
openssl genrsa -passout pass:abcd1234 -out certificates/server-key.pem 2048

# where the config file is this in "ssl.conf":
cat > certificates/ssl.conf <<EOF
[req]
prompt = no
distinguished_name = myself

[myself]
C = de
ST = NRW
L = Kerpen
O = Neunhoeffer
OU = Max
CN = xeo.9hoeffer.de

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = xeo.9hoeffer.de
EOF

# Create certificate signing request:
openssl req -new -key certificates/server-key.pem -out certificates/server-key.csr -sha512 -config certificates/ssl.conf -subj "/C=DE/ST=NRW/L=Kerpen/O=Neunhoeffer/OU=Labor/CN=xeo.9hoeffer.de/"

# Inspect it:
openssl req -in certificates/server-key.csr -text -noout

# Sign it and create a certificate:
openssl x509 -req -in certificates/server-key.csr -CA certificates/ca-root.pem -days 3650 -CAkey certificates/ca-key.pem -out certificates/server-crt.pem -extensions req_ext -extfile certificates/ssl.conf -passin pass:abcd1234 -CAcreateserial

# inspect it:
openssl x509 -in certificates/server-crt.pem -text -noout

# Creation of client authentication certificates:
openssl genrsa -passout pass:abcd1234 -out certificates/client-key.pem 2048
openssl req -new -passin pass:abcd1234 -key certificates/client-key.pem -out certificates/client-req.pem -subj "/O=ArangoDB/CN=Max/"

# Inspect:
openssl req -in certificates/client-req.pem -text -noout

cat > certificates/ssl.conf <<EOF
[req]
prompt = no
distinguished_name = myself

[myself]
O = ArangoDB
CN = ArangoDB

[client]
keyUsage = critical,Digital Signature,Key Encipherment
extendedKeyUsage = @key_usage
basicConstraints = critical,CA:FALSE

[key_usage]
1 = Any Extended Key Usage
2 = TLS Web Client Authentication
EOF

# Create client cert:
openssl x509 -req -passin pass:abcd1234 -in certificates/client-req.pem -CA certificates/ca-root.pem -CAkey certificates/ca-key.pem -set_serial 101 -extensions client -days 365 -outform PEM -out certificates/client-crt.pem -extfile certificates/ssl.conf

# Inspect:
openssl x509 -in certificates/client-crt.pem -text -noout

# Export for browser:
openssl pkcs12 -export -inkey certificates/client-key.pem -in certificates/client-crt.pem -out certificates/client.p12 -passout pass:abc

