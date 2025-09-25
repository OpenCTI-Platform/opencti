# Troubleshooting guide

This guide provides solutions to common issues you may encounter while installing, configuring, and running XTM Composer.

## Installation issues

### Post-installation verification

After installing XTM Composer, verify the installation is successful by checking these components based on your environment.

#### Development environment

##### Docker verification
```bash
# Check container status
docker ps | grep xtm-composer

# View logs
docker logs xtm-composer

# Test connectivity
docker exec xtm-composer curl -s http://localhost:8080/health
```

##### Portainer verification
1. Access Portainer dashboard
2. Navigate to Containers or Stacks
3. Check XTM Composer status (should show as "running")
4. Click on the container to view logs and statistics

#### Production environment

##### Kubernetes verification
```bash
# Check pod status
kubectl get pods -n xtm-composer

# View deployment status
kubectl get deployment -n xtm-composer

# Check logs
kubectl logs -n xtm-composer deployment/xtm-composer

# Verify service account permissions
kubectl auth can-i --list --as=system:serviceaccount:xtm-composer:xtm-composer -n xtm-composer
```

#### Common verification steps

Regardless of environment, verify:

1. **RSA Key**: Ensure the private key is properly mounted and accessible
2. **Configuration**: Confirm configuration files are loaded correctly
3. **Network**: Test connectivity to OpenCTI/OpenBAS instances
4. **Logs**: Check for any error messages or warnings

## Connection issues

If XTM Composer cannot connect to OpenCTI:

### 1. Verify URL and token

Test the connection directly using curl:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" https://opencti.example.com/graphql
```

If this fails, check:
- The URL is correct and accessible
- The token is valid
- No proxy or firewall is blocking the connection

### 2. Check network connectivity

Verify basic network connectivity:
```bash
# Test DNS resolution
ping opencti.example.com

# Test port connectivity
nc -zv opencti.example.com 443
```

If connectivity fails:
- Check DNS configuration
- Verify firewall rules
- Ensure the service is running on the expected port

### 3. SSL certificate issues

For self-signed certificates, you can temporarily set `unsecured_certificate: true` in your configuration:

```yaml
opencti:
  unsecured_certificate: true
```

**Warning**: This is not recommended for production environments. Instead:
- Add the certificate to your trusted store
- Use a valid certificate from a trusted CA

## Authentication failures

### 1. Verify RSA key

Check that your RSA key is valid:
```bash
openssl rsa -in private_key_4096.pem -check
```

Expected output:
```
RSA key ok
```

If the key is invalid:
- Regenerate the key: `openssl genrsa -out private_key_4096.pem 4096`
- Ensure it's in PKCS#8 PEM format
- Verify the key size is 4096 bits

### 2. Check file permissions

Ensure proper permissions on the private key file:
```bash
chmod 600 private_key_4096.pem
ls -la private_key_4096.pem
```

The file should be readable only by the owner.

### 3. Verify key path

Confirm the path in your configuration matches the actual key location:

```yaml
manager:
  credentials_key_filepath: "/path/to/private_key_4096.pem"
```

For Docker deployments, ensure the volume mount is correct:
```bash
docker run -v /local/path/key.pem:/keys/private_key.pem ...
```

## Orchestration issues

### Kubernetes issues

#### Verify cluster access
```bash
# Check cluster connectivity
kubectl cluster-info

# Verify permissions
kubectl auth can-i create deployments
```

If access is denied:
- Check RBAC configuration
- Verify service account permissions
- Ensure the kubeconfig is properly configured

#### Common Kubernetes errors

**"pods is forbidden"**: The service account lacks necessary permissions
- Solution: Apply the correct RBAC configuration (see Installation Guide)

**"no such host"**: Kubernetes API server cannot be reached
- Solution: Check the cluster endpoint configuration

### Docker issues

#### Check socket permissions
```bash
# Verify Docker is accessible
docker info

# Check socket permissions
ls -la /var/run/docker.sock
```

If permission denied:
- Add user to docker group: `sudo usermod -aG docker $USER`
- For container access, mount the socket: `-v /var/run/docker.sock:/var/run/docker.sock`

#### Common Docker errors

**"Cannot connect to Docker daemon"**: Docker socket not accessible
- Solution: Ensure Docker is running and socket is properly mounted

**"Network not found"**: Specified network doesn't exist
- Solution: Create the network or update configuration

### Portainer issues

#### Test API access
```bash
curl -H "X-API-Key: YOUR_KEY" https://portainer.example.com/api/endpoints
```

If this fails:
- Verify the API key is correct
- Check the Portainer URL and port
- Ensure the environment ID is correct

## Runtime issues

### Container health monitoring

XTM Composer monitors container health and can detect various runtime issues:

#### Reboot loop detection

If a container restarts more than 3 times within 5 minutes, XTM Composer detects a reboot loop. Check:

1. **Container Logs**: Review logs for startup errors
   ```bash
   # Docker
   docker logs container_name
   
   # Kubernetes
   kubectl logs pod_name -n namespace
   ```

2. **Configuration Issues**: Verify all required environment variables are set
3. **Resource Limits**: Check if the container has sufficient resources
4. **Image Availability**: Ensure the Docker image exists and is accessible

### Log collection issues

XTM Composer collects logs every `logs_schedule` interval. If logs are missing:

1. Verify the schedule configuration:
   ```yaml
   opencti:
     logs_schedule: 10  # seconds
   ```

2. Check container log availability:
   ```bash
   # Docker
   docker logs --tail 50 container_name
   
   # Kubernetes
   kubectl logs --tail 50 pod_name
   ```

3. Ensure the orchestrator has permissions to read logs

## Configuration issues

### Environment variable problems

If configuration via environment variables isn't working:

1. **Check Variable Format**: Use double underscores for nested values
   - Correct: `MANAGER__LOGGER__LEVEL=debug`
   - Incorrect: `MANAGER.LOGGER.LEVEL=debug`

2. **Verify Variable Loading**: Enable debug mode to see loaded variables
   ```yaml
   manager:
     debug:
       show_env_vars: true
   ```

3. **Priority Issues**: Remember environment variables override file configuration

### Configuration file not loading

If your configuration file isn't being loaded:

1. **Check COMPOSER_ENV**: Ensure it matches your file name
   ```bash
   export COMPOSER_ENV=production  # Loads config/production.yaml
   ```

2. **Verify File Location**: Configuration files should be in `/config` directory
3. **Check YAML Syntax**: Validate your YAML file for syntax errors

## Logging and debugging

### Enable debug logging

For detailed troubleshooting, enable debug logging:

```yaml
manager:
  logger:
    level: debug
    console: true
    format: pretty
```

Or via environment variable:
```bash
export MANAGER__LOGGER__LEVEL=debug
```

### View logs

Check logs to identify issues:

```bash
# Docker
docker logs -f xtm-composer

# Kubernetes
kubectl logs -f deployment/xtm-composer -n xtm-composer

# Binary/File-based
tail -f /var/log/xtm-composer/composer.log
```

### Common log messages

**"Successfully connected to OpenCTI"**: Connection established successfully

**"Failed to connect to platform"**: Check connection settings and network

**"Manager registered with ID"**: XTM Composer successfully registered

**"Invalid authentication"**: Check API token and credentials

**"Reboot loop detected"**: Container is continuously restarting

## Getting help

If you continue to experience issues:

1. **Check the logs** with debug level enabled
2. **Review the configuration** for any misconfigurations
3. **Verify network connectivity** between all components
4. **Consult the OpenCTI community** for additional support

For bug reports and feature requests, visit the [GitHub repository](https://github.com/OpenCTI-Platform/xtm-composer).
