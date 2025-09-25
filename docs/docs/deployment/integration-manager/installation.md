# Installation guide

## System requirements

### Runtime requirements

#### Production environment
- **Kubernetes**: v1.24 or higher
- **Namespace**: Dedicated namespace for XTM Composer
- **RBAC**: Role-based access control for pod management

#### Development environment  
- **Docker**: v20.10 or higher
- **Portainer**: v2.0 or higher (recommended for container management)
- **Docker Compose**: v2.0 or higher (optional)

### Security requirements

- **RSA Private Key**: 4096-bit RSA private key for authentication
- **Network Access**: 
  - Connectivity to OpenCTI/OpenBAS instances
  - Access to container orchestration API
- **Permissions**: 
  - Production: Kubernetes service account with appropriate RBAC
  - Development: Docker socket access or Portainer API access

## Installation methods

Create a configuration file based on your environment or add extra environment variables in the following steps.
See [Configuration Reference](configuration.md) for more information on required configuration.

## Production environment (Kubernetes)

Note: The Kubernetes installation method described here assumes that OpenCTI is already deployed on a Kubernetes cluster.

1. Create namespace:
```bash
kubectl create namespace xtm-composer
```

2. Create secret for RSA key:
```bash
# Generate key
openssl genrsa -out private_key_4096.pem 4096

# Create secret
kubectl create secret generic xtm-composer-keys \
  --from-file=private_key.pem=private_key_4096.pem \
  -n xtm-composer
```

3. Create ConfigMap for configuration:
```bash
kubectl create configmap xtm-composer-config \
  --from-file=default.yaml=config/default.yaml \
  -n xtm-composer
```

4. Create service account:

XTM Composer uses a service account to have authorization to start new pods and deployments on the cluster. 

```bash
cat <<EOF | kubectl apply -n xtm-composer -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: xtm-composer
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: xtm-composer
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "watch", "list", "create", "update", "patch", "delete", "deletecollection"]
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: xtm-composer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: xtm-composer
subjects:
- kind: ServiceAccount
  name: xtm-composer
EOF
```

5. Deploy XTM Composer:
```bash
cat <<EOF | kubectl apply -n xtm-composer -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xtm-composer
  namespace: xtm-composer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: xtm-composer
  template:
    metadata:
      labels:
        app: xtm-composer
    spec:
      containers:
      - name: xtm-composer
        image: filigran/xtm-composer:latest
        env:
        - name: COMPOSER_ENV
          value: "production"
        - name: MANAGER__ID
          value: "k8s-manager"
        - name: MANAGER__CREDENTIALS_KEY_FILEPATH
          value: "/keys/private_key.pem"
        volumeMounts:
        - name: config
          mountPath: /config
        - name: keys
          mountPath: /keys
      volumes:
      - name: config
        configMap:
          name: xtm-composer-config
      - name: keys
        secret:
          secretName: xtm-composer-keys
      serviceAccountName: xtm-composer
EOF
```

## Development environment (Docker/Portainer)

### Docker installation with CLI

```bash
# Pull the latest image
docker pull filigran/xtm-composer:latest

# Create configuration directory
mkdir -p /opt/xtm-composer/config

# Generate RSA private key
openssl genrsa -out /opt/xtm-composer/private_key_4096.pem 4096

# Run container
docker run -d \
  --name xtm-composer \
  -v /opt/xtm-composer/config:/config \
  -v /opt/xtm-composer/private_key_4096.pem:/keys/private_key.pem \
  -e COMPOSER_ENV=development \
  filigran/xtm-composer:latest
```

### Portainer installation

#### Method 1: Deploy via Portainer UI

1. **Access Portainer Dashboard**:
   - Navigate to your Portainer instance
   - Select your Docker environment

2. **Create a Stack**:
   - Go to Stacks → Add Stack
   - Name: `xtm-composer`
   - Use the following docker-compose configuration:

```yaml
version: '3.8'

services:
  xtm-composer:
    image: filigran/xtm-composer:latest
    container_name: xtm-composer
    environment:
      - COMPOSER_ENV=development
      - MANAGER__ID=dev-manager
      - MANAGER__CREDENTIALS_KEY_FILEPATH=/keys/private_key.pem
    volumes:
      - xtm-composer-config:/config
      - xtm-composer-keys:/keys
    restart: unless-stopped
    networks:
      - opencti_default

volumes:
  xtm-composer-config:
    driver: local
  xtm-composer-keys:
    driver: local

networks:
  opencti_default:
    external: true
```

3. **Configure Volumes**:
   - After deployment, access the container console via Portainer
   - Generate the RSA key:
     ```bash
     openssl genrsa -out /keys/private_key.pem 4096
     ```
   - Copy your configuration files to `/config`

#### Method 2: Deploy via Docker Compose

**Option A: Using the preconfigured OpenCTI Docker stack (Recommended)**

The [OpenCTI Docker repository](https://github.com/OpenCTI-Platform/docker) provides a complete `docker-compose.yml` that already includes:
- XTM Composer service pre-configured
- Automatic RSA key generation service
- Full OpenCTI stack integration

```bash
# Clone the repository
git clone https://github.com/OpenCTI-Platform/docker.git
cd docker

# Configure your environment
cp .env.sample .env
# Edit .env file with your settings

# Deploy the complete stack with XTM Composer
docker-compose up -d
```

**Option B: Standalone deployment**

If you prefer a standalone XTM Composer installation, create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  xtm-composer:
    image: filigran/xtm-composer:latest
    container_name: xtm-composer
    environment:
      - COMPOSER_ENV=development
      - MANAGER__ID=dev-manager
      - MANAGER__CREDENTIALS_KEY_FILEPATH=/keys/private_key.pem
    volumes:
      - ./config:/config
      - ./keys:/keys
    restart: unless-stopped
    ports:
      - "8080:8080"  # If web interface is available

volumes:
  xtm-composer-config:
  xtm-composer-keys:
```

Deploy with:
```bash
# Generate RSA key first
mkdir -p keys
openssl genrsa -out keys/private_key.pem 4096

# Deploy the stack
docker-compose up -d
```

## Alternative installation methods

### Binary installation

For advanced users who need custom builds or want to contribute to development.

#### Prerequisites

- **Rust**: 1.70.0 or higher
- **Git**: For cloning the repository
- **OpenSSL**: For generating RSA keys

#### Build from source

```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repository
git clone https://github.com/OpenCTI-Platform/xtm-composer.git
cd xtm-composer

# Build release binary
cargo build --release

# Generate RSA key
openssl genrsa -out ./private_key_4096.pem 4096

# Run the binary
./target/release/xtm-composer
```

## Troubleshooting

For common issues and their solutions, see the [Troubleshooting Guide](troubleshooting.md).

## Next steps

1. Configure XTM Composer - See [Configuration Reference](configuration.md)
2. Connect to OpenCTI/OpenBAS - See [Quick Start](quick-start.md)
3. Verify integration management functionality
