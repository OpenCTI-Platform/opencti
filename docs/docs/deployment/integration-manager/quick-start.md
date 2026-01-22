# Quick start guide

This guide will help you get XTM Composer up and running quickly with OpenCTI.

## Prerequisites

Before starting, ensure you have:
- XTM Composer installed (see [Installation Guide](installation.md))
- Access to an OpenCTI instance
- OpenCTI API token
- RSA private key (4096-bit)

## Step 1: Generate RSA private key

Generate a 4096-bit RSA private key for authentication:

```bash
openssl genrsa -out private_key_4096.pem 4096
```

## Step 2: Basic configuration

Create a configuration file based on your environment.

### Option A: Using Configuration File

Create `config/production.yaml`:

```yaml
manager:
  id: "my-manager-001"
  name: "Production Manager"
  credentials_key_filepath: "/path/to/private_key_4096.pem"
  logger:
    level: info
    format: json

opencti:
  enable: true
  url: "https://opencti.example.com"
  token: "your-opencti-api-token"
  daemon:
    selector: kubernetes  # or 'docker' or 'portainer'
```

### Option B: Using Environment Variables

Set configuration through environment variables:

```bash
export COMPOSER_ENV=production
export MANAGER__ID="my-manager-001"
export MANAGER__CREDENTIALS_KEY_FILEPATH="/path/to/private_key_4096.pem"
export OPENCTI__URL="https://opencti.example.com"
export OPENCTI__TOKEN="your-opencti-api-token"
export OPENCTI__DAEMON__SELECTOR="kubernetes"
```

## Step 3: Choose your orchestration platform

### For Kubernetes

```yaml
opencti:
  daemon:
    selector: kubernetes
    kubernetes:
      image_pull_policy: IfNotPresent
```

### For Docker

```yaml
opencti:
  daemon:
    selector: docker
    docker:
      network_mode: bridge
```

**Note**: Docker mode requires socket access:
```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock ...
```

### For Portainer

```yaml
opencti:
  daemon:
    selector: portainer
    portainer:
      api: "https://portainer.example.com:9443"
      api_key: "your-portainer-api-key"
      env_id: "3"
      env_type: "docker"
```

## Step 4: Run XTM Composer

### Using Docker

```bash
docker run -d \
  --name xtm-composer \
  -v $(pwd)/config:/config \
  -v $(pwd)/private_key_4096.pem:/keys/private_key.pem \
  -e COMPOSER_ENV=production \
  filigran/xtm-composer:latest
```

### Using Binary

```bash
COMPOSER_ENV=production ./xtm-composer
```

## Step 5: Verify connection

Check the logs to verify XTM Composer is connected to OpenCTI:

```bash
# Docker
docker logs xtm-composer

# Binary/Systemd
tail -f /var/log/xtm-composer/composer.log
```

You should see messages like:
```
INFO  Starting XTM Composer
INFO  Connecting to OpenCTI at https://opencti.example.com
INFO  Successfully connected to OpenCTI
INFO  Manager registered with ID: my-manager-001
```

## Step 6: Verify in OpenCTI

1. Log into your OpenCTI instance
2. Navigate to **Data > Connectors**
3. You should see your XTM Composer manager listed
4. Connectors managed by XTM Composer will show the manager ID

## Common configuration examples

### Development environment

```yaml
manager:
  id: "dev-manager"
  credentials_key_filepath: "./private_key_4096.pem"
  logger:
    level: debug
    format: pretty
    console: true
  debug:
    show_env_vars: true

opencti:
  enable: true
  url: "http://localhost:4000"
  token: "development-token"
  daemon:
    selector: docker
```

### Production with high availability

```yaml
manager:
  id: "prod-manager-ha"
  execute_schedule: 5      # Check every 5 seconds
  ping_alive_schedule: 30  # Ping every 30 seconds
  logger:
    level: warn
    format: json
    directory: true
    console: false

opencti:
  enable: true
  url: "https://opencti.prod.example.com"
  token: "${OPENCTI_TOKEN}"  # Use environment variable
  logs_schedule: 5
  daemon:
    selector: kubernetes
    kubernetes:
      image_pull_policy: Always
```

## Troubleshooting

For common issues and their solutions, see the [Troubleshooting Guide](troubleshooting.md).

## Next steps

- Review the complete [Configuration Reference](configuration.md)
- Set up monitoring and alerting
- Configure connector-specific settings
- Implement security best practices
- Join the OpenCTI community for support
