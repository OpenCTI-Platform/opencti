# Security deep dive

## Database and storage architecture

### 1. Database type for connector configurations and secrets

XTM Composer **does not rely on a traditional database**. Instead, it employs a **pull-based architecture** where:

- Connector configurations and secrets are stored in the **OpenCTI/OpenAEV platform’s database** (not within XTM Composer).
- XTM Composer periodically retrieves these configurations via **GraphQL API calls**.
- The system functions as a **stateless orchestrator**, persisting no connector data locally.

### 2. Multi-tenancy and database isolation

Since XTM Composer lacks its own database:

- The **multi-tenancy model** depends on the **OpenCTI/OpenAEV platform deployment**.
- Each XTM Composer instance is configured with a **dedicated platform URL and authentication token**.
- In multi-tenant environments, **separate OpenCTI instances per tenant** are typically deployed, each paired with its own XTM Composer.

## Encryption implementation

### 1. Hardware-backed encryption keys (HSM/TPM)

The **RSA private key** used for decryption:

- Is **not hardware-backed by default**.
- Is loaded from either a **file path** or an **environment variable**.
- Relies on a **software-based RSA implementation** (`rsa` crate v0.9.8).

### 2. AES-256 encryption mode

XTM Composer implements **AES-256-GCM (Galois/Counter Mode)**:

- "This mode provides **authenticated encryption**, ensuring both **confidentiality and integrity** for stored secrets.

### 3. Private key storage and security

The **RSA private key** can be stored in the following ways:

- **File-based**: Specified via `credentials_key_filepath`.
- **Environment variable**: Provided via `MANAGER__CREDENTIALS_KEY`.
- **Format**: **PKCS#8 PEM** (4096-bit RSA recommended).
- **Access control**: Relies on **OS-level file permissions** and **environment variable security**.
- **Key rotation**: No automated rotation policy by default, this should be implemented by the platform  administrators

### 4. Private key handling and network security

- The **RSA private key** is **loaded exclusively into the XTM Composer’s runtime** and used **solely for decrypting sensitive values such as API keys**.
- **Only the RSA public key** is transmitted over the network during **API calls**, ensuring the private key remains isolated.

## Access control and security

### 1. Database access restrictions

Since configurations are stored in **OpenCTI/OpenAEV**:

- XTM Composer authenticates using a **Bearer token** for GraphQL API access.
- The token is configured in the settings and included in every request.
- Access control is enforced at the **API level**, not the database level.
- Each composer instance uses a **unique authentication token**.

### 2. Access auditing and monitoring

The current implementation includes:

- **Logging**: Comprehensive logging via the `tracing` crate, with configurable verbosity.
- **Log collection**: Periodic aggregation and reporting of **container logs**.
- **Audit trail**: Primarily maintained in **OpenCTI/OpenAEV platform logs**, not within XTM Composer.

### 3. Database backup policy

Since XTM Composer is **stateless**:

- **No local backups** are required for XTM Composer itself.
- Backup requirements apply to the **OpenCTI/OpenAEV platform database**.
- Configuration recovery involves **restoring the platform database**.

## Security architecture summary

The **hybrid encryption scheme** operates as follows:

1. **Platform side**:
    - Generates an **AES-256-GCM key**.
    - Encrypts sensitive configuration values.
    - Encrypts the AES key with an **RSA public key**.
2. **Composer side**:
    - Decrypts the AES key using the **RSA private key**.
    - Decrypts configuration values.
3. **Wire format**:
    
    ```
    [Version: 1 byte][RSA-encrypted AES key + IV: 512 bytes][AES-GCM encrypted data: N bytes]
    ```
    

## Production deployment recommendations

1. **Key Management**: Integrate with a **Key Management System (KMS)** or **HSM** for the RSA private key.
2. **Secret Storage**: Ensure the RSA private key file has **restrictive permissions (600)** and is stored on **encrypted storage**.
3. **Key Rotation**: Implement an **automated key rotation policy**.
4. **Zero-Trust**: Enforce **network segmentation** and **mutual TLS (mTLS)** for API communications.
5. **Monitoring**: Set up **alerts for reboot loops** and **authentication failures**.
