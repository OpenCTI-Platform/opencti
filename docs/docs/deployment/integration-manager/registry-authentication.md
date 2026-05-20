# Private Registry

## Overview

XTM Composer supports the deployment of containers from both public and private Docker registries.  
Registry authentication is configured through the OpenCTI daemon settings and automatically applied by the Integration Manager during connector deployment.

This page explains how to configure:

- Configuration for private Docker registries
- Kubernetes automatic secret creation
- Registry prefix resolution

---

## Configuration

The Integration Manager automatically uses the registry configuration defined under `opencti.daemon.registry`.  
No additional configuration is required inside Composer.

```yaml
opencti:
  daemon:
    registry:
      server: "registry.example.com"  # Default: docker.io
      username: "myuser"              # Required for Kubernetes auto-creation
      password: "mypassword"          # Required for Kubernetes auto-creation
      email: "user@example.com"       # Optional
```

### Environment Variables

```bash
export OPENCTI__DAEMON__REGISTRY__SERVER="registry.example.com"
export OPENCTI__DAEMON__REGISTRY__USERNAME="myuser"
export OPENCTI__DAEMON__REGISTRY__PASSWORD="mypassword"
export OPENCTI__DAEMON__REGISTRY__EMAIL="user@example.com"  # Optional
```

### Required Fields

- **server**: Registry URL (defaults to `docker.io` if not specified)
- **username**: Registry username (required for Kubernetes secret creation)
- **password**: Registry password (required for Kubernetes secret creation)
- **email**: User email (optional)

---

## Kubernetes Secret Auto-Creation

When using the **Kubernetes orchestrator**, XTM Composer automatically creates an `imagePullSecret` at startup if credentials are configured.

### Behavior

**With credentials configured:**

1. At startup, the orchestrator deletes any existing secret named `opencti-registry-auth`
2. Creates a new secret with your credentials
3. Automatically attaches this secret to deployed connector pods

**Without credentials:**

- No secret is created
- You can manually create and configure your own secret if needed

### Secret Details

- **Name**: `opencti-registry-auth` (hardcoded)
- **Type**: `kubernetes.io/dockerconfigjson`
- **Lifecycle**: Recreated on each startup if credentials present

### Expected Startup Logs

```
INFO orchestrator="kubernetes" secret="opencti-registry-auth" Deleting existing imagePullSecret if present
INFO orchestrator="kubernetes" secret="opencti-registry-auth" server="registry.example.com" Creating imagePullSecret for private registry
INFO orchestrator="kubernetes" secret="opencti-registry-auth" Successfully created imagePullSecret
```

### Required Kubernetes Permissions

Your ServiceAccount must have these permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: xtm-composer-role
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "delete"]
```

### Troubleshooting

**Secret creation fails:**

- Check that your ServiceAccount has the required RBAC permissions
- Verify credentials are correct
- Check startup logs for error messages

**Pods can't pull images:**

- Verify the secret exists: `kubectl get secret opencti-registry-auth`
- Check secret is attached to pods: `kubectl describe pod <pod-name>`
- Ensure registry server is accessible from the cluster

---

## Registry Prefix Resolution

The Integration Manager automatically handles registry prefixes in image names:

- If the image name already includes the registry, it will not prepend anything.
- If no registry is included, the `server` from the registry configuration is automatically prefixed.
- This prevents double-prefixing and ensures images are pulled from the correct registry.

Example:

```yaml
# Image without prefix
image: "opencti/connector-example:1.0.0"

# After resolution
image: "registry.example.com/opencti/connector-example:1.0.0"
```

See also: [Proxy Support](proxy-configuration.md)