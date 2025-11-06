# Abstract Machines Certificate Manager

[![codecov](https://codecov.io/gh/absmach/certs/graph/badge.svg?token=M1rtItXAFd)](https://codecov.io/gh/absmach/certs)
[![license][license]](LICENSE)

Abstract Machines Certicate Manager is an open source, lightweight, scalable, and customizable certs manager. This PKI (Public Key Infrastructure) service provides a comprehensive set of features for managing digital certificates. It includes an SDK, CLI, and API that enable the following functionality:

- Certificate Issuance: Issue new certificates for entities, specifying parameters like the certificate type, TTL, IP addresses, and subject options.
- Certificate Renewal: Renew existing certificates in the database.
- Certificate Revocation: Revoke certificates that are no longer valid or trusted.
- Certificate Retrieval: Retrieve certificate records from the database, including options to view, download, and get OCSP responses.
- Certificate Listing: List certificates based on various filters, such as entity ID, expiry time, and revocation status.
- Certificate Authority (CA) Management: Retrieve the chain of CA certificates (root and intermediate) and generate Certificate Revocation Lists (CRLs).

## Architecture

The certs service has transitioned from a custom PKI implementation to using [OpenBao](https://openbao.org/) (an open-source fork of HashiCorp Vault) for production-grade PKI management. This provides enterprise-level security features including:

- **Automated CA Management**: Root and intermediate CA certificate generation and rotation
- **Secure Key Storage**: Private keys are stored securely within OpenBao's encrypted backend
- **OCSP & CRL Support**: Built-in support for certificate revocation checking
- **AppRole Authentication**: Service-to-service authentication using OpenBao's AppRole auth method
- **Namespace Support**: Multi-tenancy support through OpenBao namespaces

### PKI Configuration

The PKI infrastructure is automatically configured during service startup via the [`docker/openbao-entrypoint.sh`](docker/openbao-entrypoint.sh) script. This entrypoint script handles:

1. **OpenBao Initialization**: Sets up OpenBao server and generates encryption keys (uses Shamir's Secret Sharing to split the master key into 5 pieces, requiring any 3 to unlock)
2. **Root CA Generation**: Creates the root CA certificate with configurable subject fields (organization, country, etc.)
3. **Intermediate CA Setup**: Generates an intermediate CA certificate signed by the root CA for day-to-day certificate operations
4. **Role Configuration**: Defines PKI roles with specific permissions and constraints for certificate issuance
5. **AppRole Setup**: Configures secure authentication so the certs service can communicate with OpenBao
6. **Policy Management**: Creates access control policies that define what operations are allowed (issue, revoke, sign certificates)

The entrypoint script is configurable via environment variables (see `docker/.env`) and ensures that the PKI is properly initialized before the certs service starts.

## Features

- **OpenBao-Backed PKI**: Enterprise-grade PKI infrastructure powered by OpenBao
- **Certificate Lifecycle Management**: Automated certificate renewal and revocation
- **Active Revocation**: Real-time certificate status checking via CRL and OCSP
- **RESTful API**: Comprehensive API for certificate management operations
- **Go SDK**: Easy-to-use SDK for Go applications
- **CLI Tool**: Command-line interface for certificate operations
- **Multi-Tenancy**: Support for domain-based isolation via SuperMQ integration

## Prerequisites

The following are needed to run absmach certs:

- [Docker](https://docs.docker.com/install/) (version 28.5.1 or higher)
- [SuperMQ](https://github.com/absmach/supermq) (version 0.18.2 or higher) running instance (required for authorization, domains, users management)

Developing absmach certs will also require:

- [Go](https://golang.org/doc/install) (version 1.25.3 or higher)
- [Protobuf](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation) (version 32.0 or higher)

## Install

Once the prerequisites are installed, clone the repo

```bash
git clone https://github.com/absmach/certs.git
cd certs
```

> **Note:**
> Ensure SuperMQ is running before starting the certs service, as it depends on SuperMQ for authorization, domain management, and user management.

### Running with Docker Compose

Execute the following commands from the project's root:

```bash
docker compose -f docker/docker-compose.yaml --env-file docker/.env -p absmach up
```

This will bring up the certs docker services and interconnect them. This command can also be executed using the project's included Makefile:

```bash
make run
```

### Running in Development Mode

To run the service in development mode with all dependencies:

```bash
make all && make docker_dev && make run args="-d"
```

This command will:
1. Build the service binaries
2. Start the required Docker services (PostgreSQL, OpenBao, etc.)
3. Run the certs service in detached mode (runs in the background, freeing up your terminal)

## Usage

### SDK

 Absmach certs provides an SDK that can be imported and used in your Go applications. Here's an example of how to use the SDK:

 ```go
 cert , _ := sdk.IssueCert("entityID", "10h", []string{"ipAddr1", "ipAddr2"}, sdk.Options{CommonName: "commonName"})
fmt.Println(cert)
 ```

### CLI

Absmach certs also provides a command-line interface (CLI) for interacting with the service. The CLI supports the following commands:

- `issue`: Issue a new certificate
- `get`: List certificates
- `token`: Gets download token
- `download`: Downloads a certificate
- `renew`: Renew an existing certificate
- `revoke`: Revoke a certificate
- `view`: Retrieve a certificate
- `generate-crl`: Generate a Certificate Revocation List (CRL)
- `token-ca`: Gets CA download token
- `download-ca`: Retrieve the chain of CA certificates

### API

The absmach certs exposes a RESTful API that can be used to interact with the service programmatically. Here is an example using cURL:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"ip_addresses":["191.168.101.16"],"ttl":"10h","options":{"organization":["organization_name"]}}' \
  http://localhost:9010/certs/issue/64eeb24e-6154-48c4-ad32-e4fb02ed32da\?common_name\=thing
```

## Contributing

Thank you for your interest in Absmach certs and the desire to contribute!

1. Take a look at our [open issues](https://github.com/absmach/certs/issues).
2. Checkout the [contribution guide](CONTRIBUTING.md) to learn more about our style and conventions.
3. Make your changes compatible to our workflow.

Also, explore our [contrib][contrib] repository for extra services such as Cassandra, InfluxDB, MongoDB readers and writers, LoRa, OPC UA support, Digital Twins, and more. If you have a contribution that is not a good fit for the core monorepo (it's specific to your use case, it's an additional feature or a new service, it's optional or an add-on), this is a great place to submit the pull request.

## Community

- [Gitter][gitter]
- [Twitter][twitter]

## License

[Apache-2.0](LICENSE)

[contrib]: https://www.github.com/absmach/mg-contrib
[gitter]: https://gitter.im/absmach/magistrala?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge
[license]: https://img.shields.io/badge/license-Apache%20v2.0-blue.svg
[twitter]: https://twitter.com/absmach
