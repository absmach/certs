#!/bin/sh
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

set -e

apk add --no-cache jq

# Create required directories
mkdir -p /opt/openbao/config /opt/openbao/data /opt/openbao/logs

cat > /opt/openbao/config/config.hcl << 'EOF'
storage "file" {
  path = "/opt/openbao/data"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
ui = true
log_level = "Info"
disable_mlock = true
# API timeout settings
default_lease_ttl = "168h"
max_lease_ttl = "720h"
EOF

export BAO_ADDR=http://127.0.0.1:8200

# Check if we have pre-configured unseal keys and root token
if [ -n "$SMQ_OPENBAO_UNSEAL_KEY_1" ] && [ -n "$SMQ_OPENBAO_UNSEAL_KEY_2" ] && [ -n "$SMQ_OPENBAO_UNSEAL_KEY_3" ] && [ -n "$SMQ_OPENBAO_ROOT_TOKEN" ]; then
  echo "Using pre-configured unseal keys and root token..."
  bao server -config=/opt/openbao/config/config.hcl > /opt/openbao/logs/server.log 2>&1 &
  BAO_PID=$!
  sleep 5
  
  bao operator unseal "$SMQ_OPENBAO_UNSEAL_KEY_1"
  bao operator unseal "$SMQ_OPENBAO_UNSEAL_KEY_2"
  bao operator unseal "$SMQ_OPENBAO_UNSEAL_KEY_3"
  
  export BAO_TOKEN=$SMQ_OPENBAO_ROOT_TOKEN
else
  # Initialize OpenBao if not already done
  if [ ! -f /opt/openbao/data/init.json ]; then
    echo "Initializing OpenBao for the first time..."
    bao server -config=/opt/openbao/config/config.hcl > /opt/openbao/logs/server.log 2>&1 &
    BAO_PID=$!
    sleep 5

    # Initialize with 5 key shares and threshold of 3
    bao operator init -key-shares=5 -key-threshold=3 -format=json > /opt/openbao/data/init.json

    # Extract unseal keys and root token
    UNSEAL_KEY_1=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[0]')
    UNSEAL_KEY_2=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[1]')
    UNSEAL_KEY_3=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[2]')
    ROOT_TOKEN=$(cat /opt/openbao/data/init.json | jq -r '.root_token')

    # Unseal OpenBao
    bao operator unseal "$UNSEAL_KEY_1"
    bao operator unseal "$UNSEAL_KEY_2"
    bao operator unseal "$UNSEAL_KEY_3"

    export BAO_TOKEN=$ROOT_TOKEN
    echo "OpenBao initialized successfully!"
  else
    echo "OpenBao already initialized, starting server..."
    bao server -config=/opt/openbao/config/config.hcl > /opt/openbao/logs/server.log 2>&1 &
    BAO_PID=$!
    sleep 5

    # Check if OpenBao is sealed and unseal if necessary
    if bao status -format=json | jq -e '.sealed == true' >/dev/null; then
      echo "OpenBao is sealed, unsealing..."
      UNSEAL_KEY_1=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[0]')
      UNSEAL_KEY_2=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[1]')
      UNSEAL_KEY_3=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[2]')

      bao operator unseal "$UNSEAL_KEY_1"
      bao operator unseal "$UNSEAL_KEY_2"
      bao operator unseal "$UNSEAL_KEY_3"
      echo "OpenBao unsealed successfully!"
    else
      echo "OpenBao is already unsealed!"
    fi

    ROOT_TOKEN=$(cat /opt/openbao/data/init.json | jq -r '.root_token')
    export BAO_TOKEN=$ROOT_TOKEN
  fi
fi

# Configure OpenBao PKI and AppRole if not already configured
if [ ! -f /opt/openbao/data/configured ]; then
  echo "Configuring OpenBao PKI and AppRole..."
  
  # Create namespace if specified
  if [ -n "$SMQ_OPENBAO_NAMESPACE" ]; then
    if bao namespace create "$SMQ_OPENBAO_NAMESPACE" 2>/tmp/ns_error; then
      export BAO_NAMESPACE="$SMQ_OPENBAO_NAMESPACE"
      echo "$SMQ_OPENBAO_NAMESPACE" > /opt/openbao/data/namespace
      echo "Created namespace: $SMQ_OPENBAO_NAMESPACE"
    else
      if grep -q "namespace already exists" /tmp/ns_error; then
        export BAO_NAMESPACE="$SMQ_OPENBAO_NAMESPACE"
        echo "$SMQ_OPENBAO_NAMESPACE" > /opt/openbao/data/namespace
        echo "Using existing namespace: $SMQ_OPENBAO_NAMESPACE"
      else
        echo "ERROR: Failed to create namespace $SMQ_OPENBAO_NAMESPACE:" >&2
        cat /tmp/ns_error >&2
        exit 1
      fi
    fi
    rm -f /tmp/ns_error
  fi

  # Enable authentication methods and secrets engines
  if ! bao auth enable approle 2>/tmp/auth_error; then
    if ! grep -q "already in use" /tmp/auth_error; then
      echo "ERROR: Failed to enable AppRole auth method:" >&2
      cat /tmp/auth_error >&2
      exit 1
    fi
    echo "AppRole already enabled"
  fi
  rm -f /tmp/auth_error

  # Enable PKI secrets engine
  if ! bao secrets enable -path=pki pki 2>/tmp/pki_error; then
    # If the failure wasn’t because the mount already exists, abort
    if ! grep -q "already in use" /tmp/pki_error; then
      echo "ERROR: Failed to enable PKI secrets engine:" >&2
      cat /tmp/pki_error >&2
      exit 1
    fi
    echo "PKI already enabled"
  fi
  rm -f /tmp/pki_error

  # Configure PKI engine
  bao secrets tune -max-lease-ttl=87600h pki

  # Validate required CA environment variables
  for var in SMQ_OPENBAO_PKI_CA_CN SMQ_OPENBAO_PKI_CA_O SMQ_OPENBAO_PKI_CA_C; do
    eval "value=\$var"
    if [ -z "$value" ]; then
      echo "ERROR: Required environment variable $var is not set" >&2
      exit 1
    fi
  done

   # Generate root CA certificate
  bao write -field=certificate pki/root/generate/internal \
    common_name="$SMQ_OPENBAO_PKI_CA_CN" \
    organization="$SMQ_OPENBAO_PKI_CA_O" \
    ou="$SMQ_OPENBAO_PKI_CA_OU" \
    country="$SMQ_OPENBAO_PKI_CA_C" \
    locality="$SMQ_OPENBAO_PKI_CA_L" \
    province="$SMQ_OPENBAO_PKI_CA_ST" \
    street_address="$SMQ_OPENBAO_PKI_CA_ADDR" \
    postal_code="$SMQ_OPENBAO_PKI_CA_PO" \
    ttl=87600h \
    key_bits=2048 \
    exclude_cn_from_sans=true

  if [ $? -eq 0 ]; then
    echo "Root CA certificate generated successfully!"
  else
    echo "ERROR: Failed to generate root CA certificate" >&2
    exit 1
  fi

  # Configure CA and CRL URLs
  bao write pki/config/urls \
    issuing_certificates='http://127.0.0.1:8200/v1/pki/ca' \
    crl_distribution_points='http://127.0.0.1:8200/v1/pki/crl'

  echo "Creating PKI role: ${SMQ_OPENBAO_PKI_ROLE}"
  bao write pki/roles/"${SMQ_OPENBAO_PKI_ROLE}" \
    allow_any_name=true \
    enforce_hostnames=false \
    allow_ip_sans=true \
    allow_localhost=true \
    max_ttl=720h \
    ttl=720h \
    key_bits=2048

  # Create PKI policy
  cat > /opt/openbao/config/pki-policy.hcl << EOF
# PKI certificate operations
path "pki/issue/${SMQ_OPENBAO_PKI_ROLE}" {
  capabilities = ["create", "update"]
}
path "pki/sign/${SMQ_OPENBAO_PKI_ROLE}" {
  capabilities = ["create", "update"]
}
path "pki/certs" {
  capabilities = ["list"]
}
path "pki/cert/*" {
  capabilities = ["read"]
}
path "pki/revoke" {
  capabilities = ["create", "update"]
}
path "pki/ca" {
  capabilities = ["read"]
}
path "pki/ca_chain" {
  capabilities = ["read"]
}
path "pki/crl" {
  capabilities = ["read"]
}
# Token management
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
# System lease renewal
path "sys/renew/*" {
  capabilities = ["update"]
}
EOF

  bao policy write pki-policy /opt/openbao/config/pki-policy.hcl

  # Create AppRole
  echo "Creating AppRole: ${SMQ_OPENBAO_PKI_ROLE:-certs}"
  bao write auth/approle/role/"${SMQ_OPENBAO_PKI_ROLE:-certs}" \
    token_policies=pki-policy \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true \
    secret_id_ttl=24h

  # Set custom role ID if provided
  if [ -n "$SMQ_OPENBAO_APP_ROLE" ]; then
    echo "Setting custom role ID: $SMQ_OPENBAO_APP_ROLE"
    bao write auth/approle/role/"${SMQ_OPENBAO_PKI_ROLE:-certs}"/role-id role_id="$SMQ_OPENBAO_APP_ROLE"
  fi

  # Set custom secret ID if provided
  if [ -n "$SMQ_OPENBAO_APP_SECRET" ]; then
    echo "Setting custom secret ID"
    bao write auth/approle/role/"${SMQ_OPENBAO_PKI_ROLE:-certs}"/custom-secret-id secret_id="$SMQ_OPENBAO_APP_SECRET"
  fi

  # Generate service token for additional access
  SERVICE_TOKEN=$(bao write -field=token auth/token/create \
    policies=pki-policy \
    ttl=24h \
    renewable=true \
    display_name="certs-service")

  echo "SERVICE_TOKEN=$SERVICE_TOKEN" > /opt/openbao/data/service_token
  
  # Mark configuration as complete
  touch /opt/openbao/data/configured
  echo "OpenBao configuration completed successfully!"
else
  echo "OpenBao already configured, skipping setup..."
  
  # Restore namespace if it exists
  if [ -f /opt/openbao/data/namespace ] && [ -n "$SMQ_OPENBAO_NAMESPACE" ]; then
    SAVED_NAMESPACE=$(cat /opt/openbao/data/namespace)
    if [ "$SAVED_NAMESPACE" = "$SMQ_OPENBAO_NAMESPACE" ]; then
      export BAO_NAMESPACE="$SMQ_OPENBAO_NAMESPACE"
      echo "Restored namespace: $SMQ_OPENBAO_NAMESPACE"
    fi
  fi
fi

echo "================================"
echo "OpenBao Production Setup Complete"
echo "================================"
echo "OpenBao Address: http://localhost:8200"
echo "UI Available at: http://localhost:8200/ui"
echo "PKI Role: ${SMQ_OPENBAO_PKI_ROLE}"
echo "================================"
echo "IMPORTANT: Store the init.json file securely!"
echo "It contains unseal keys and root token!"
echo "================================"

echo "OpenBao is ready for certs service on port 8200"

if [ -n "$BAO_PID" ]; then
  wait $BAO_PID
else
  echo "ERROR: OpenBao server process ID not available" >&2
  exit 1
fi
