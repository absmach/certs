# Enhanced OpenBao PKI Setup

This enhanced OpenBao entrypoint script provides comprehensive certificate authority (CA) setup with support for Subject Alternative Names (SANs) including IP addresses, DNS names, URIs, and email addresses.

## Features

- **Enhanced CA Certificate Generation**: Support for multiple IP addresses, DNS names, URIs, and email addresses
- **Flexible Configuration**: Extensive environment variable support for all certificate fields
- **Production Ready**: Support for pre-configured unseal keys and tokens
- **Comprehensive PKI Role**: Enhanced role configuration for maximum flexibility
- **Docker Integration**: Full integration with Docker Compose

## Quick Start

1. Copy the example environment file:
   ```bash
   cp openbao.env.example openbao.env
   ```

2. Customize the environment variables in `openbao.env` for your organization and network.

3. Run with Docker Compose:
   ```bash
   docker-compose up -d openbao
   ```

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SMQ_OPENBAO_PKI_CA_CN` | Common Name for CA | `My Company Root CA` |
| `SMQ_OPENBAO_PKI_CA_O` | Organization name | `My Company Inc` |
| `SMQ_OPENBAO_PKI_CA_C` | Country code (2 letters) | `US` |

### Optional Certificate Fields

| Variable | Description | Example |
|----------|-------------|---------|
| `SMQ_OPENBAO_PKI_CA_OU` | Organizational Unit | `IT Department` |
| `SMQ_OPENBAO_PKI_CA_L` | Locality/City | `San Francisco` |
| `SMQ_OPENBAO_PKI_CA_ST` | State/Province | `California` |
| `SMQ_OPENBAO_PKI_CA_ADDR` | Street Address | `123 Main Street` |
| `SMQ_OPENBAO_PKI_CA_PO` | Postal Code | `94105` |

### Subject Alternative Names (SANs)

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `SMQ_OPENBAO_PKI_CA_DNS_NAMES` | DNS names (comma-separated) | `localhost,openbao,vault` | `localhost,pki.company.com,*.company.com` |
| `SMQ_OPENBAO_PKI_CA_IP_ADDRESSES` | IP addresses (comma-separated) | `127.0.0.1,::1` | `127.0.0.1,192.168.1.100,10.0.0.50` |
| `SMQ_OPENBAO_PKI_CA_URI_SANS` | URI SANs (comma-separated) | - | `https://pki.company.com,https://vault.company.com` |
| `SMQ_OPENBAO_PKI_CA_EMAIL_ADDRESSES` | Email addresses (comma-separated) | - | `admin@company.com,pki@company.com` |

### OpenBao Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SMQ_OPENBAO_PKI_ROLE` | PKI role name | `certs` |
| `SMQ_OPENBAO_NAMESPACE` | OpenBao namespace | - |
| `SMQ_OPENBAO_APP_ROLE` | Custom AppRole ID | Generated |
| `SMQ_OPENBAO_APP_SECRET` | Custom Secret ID | Generated |

### Production Setup (Optional)

For production environments, you can provide pre-configured unseal keys and root token:

| Variable | Description |
|----------|-------------|
| `SMQ_OPENBAO_UNSEAL_KEY_1` | First unseal key |
| `SMQ_OPENBAO_UNSEAL_KEY_2` | Second unseal key |
| `SMQ_OPENBAO_UNSEAL_KEY_3` | Third unseal key |
| `SMQ_OPENBAO_ROOT_TOKEN` | Root token |

## Usage Examples

### Basic Setup

```bash
# Required fields
export SMQ_OPENBAO_PKI_CA_CN="My Company Root CA"
export SMQ_OPENBAO_PKI_CA_O="My Company Inc"
export SMQ_OPENBAO_PKI_CA_C="US"

# Basic SANs for local development
export SMQ_OPENBAO_PKI_CA_DNS_NAMES="localhost,openbao,vault"
export SMQ_OPENBAO_PKI_CA_IP_ADDRESSES="127.0.0.1,::1"
```

### Enterprise Setup

```bash
# Required fields
export SMQ_OPENBAO_PKI_CA_CN="ACME Corp Root Certificate Authority"
export SMQ_OPENBAO_PKI_CA_O="ACME Corporation"
export SMQ_OPENBAO_PKI_CA_C="US"

# Complete organizational info
export SMQ_OPENBAO_PKI_CA_OU="Information Technology"
export SMQ_OPENBAO_PKI_CA_L="New York"
export SMQ_OPENBAO_PKI_CA_ST="New York"
export SMQ_OPENBAO_PKI_CA_ADDR="123 Corporate Blvd"
export SMQ_OPENBAO_PKI_CA_PO="10001"

# Enterprise SANs
export SMQ_OPENBAO_PKI_CA_DNS_NAMES="pki.acme.com,vault.acme.com,*.acme.com,*.internal.acme.com"
export SMQ_OPENBAO_PKI_CA_IP_ADDRESSES="10.0.1.100,10.0.1.101,192.168.100.50"
export SMQ_OPENBAO_PKI_CA_URI_SANS="https://pki.acme.com,https://vault.acme.com"
export SMQ_OPENBAO_PKI_CA_EMAIL_ADDRESSES="pki-admin@acme.com,security@acme.com"
```

### Kubernetes/Multi-Node Setup

```bash
# For Kubernetes or multi-node deployments
export SMQ_OPENBAO_PKI_CA_DNS_NAMES="openbao,openbao.default,openbao.default.svc,openbao.default.svc.cluster.local,localhost"
export SMQ_OPENBAO_PKI_CA_IP_ADDRESSES="127.0.0.1,::1,10.96.0.1,172.20.0.1"
```

## PKI Role Configuration

The enhanced setup creates a PKI role with the following capabilities:

- **Multiple Domain Support**: Wildcard and subdomain certificates
- **IP Address Support**: Certificates with IP SANs
- **Flexible Usage**: Both server and client authentication
- **CSR Support**: Can sign certificate signing requests
- **Extended Key Usage**: Configurable for various certificate types

## Accessing the CA Certificate

Once OpenBao is running, you can retrieve the CA certificate:

```bash
# Get CA certificate
curl -s http://localhost:8200/v1/pki/ca/pem

# Get CA certificate chain
curl -s http://localhost:8200/v1/pki/ca_chain
```

## Security Considerations

1. **Store Unseal Keys Securely**: The init.json file contains sensitive data
2. **Use Strong Passwords**: If deploying in production
3. **Network Security**: Restrict access to OpenBao ports
4. **Regular Rotation**: Plan for certificate rotation
5. **Backup Strategy**: Implement proper backup procedures

## Troubleshooting

### Common Issues

1. **Initialization Fails**: Check that all required environment variables are set
2. **Certificate Generation Fails**: Verify SANs format (comma-separated, no spaces)
3. **Network Access Issues**: Ensure DNS names and IP addresses match your network
4. **Permission Issues**: Verify Docker container has proper permissions

### Debug Mode

To enable debug logging, set:
```bash
export BAO_LOG_LEVEL=debug
```

### Validation

Check the generated CA certificate:
```bash
# Get certificate details
curl -s http://localhost:8200/v1/pki/ca/pem | openssl x509 -text -noout
```

This will show all the SANs and certificate details to verify proper configuration.
