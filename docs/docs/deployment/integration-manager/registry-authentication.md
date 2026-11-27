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
      server: "registry.example.com"  # Optional, no default: prepended to the image names
      username: "myuser"              # Required for authentication
      password: "mypassword"          # Required for authentication
      email: "user@example.com"       # Optional
```

### Environment Variables

```bash
export OPENCTI__DAEMON__REGISTRY__SERVER="registry.example.com"
export OPENCTI__DAEMON__REGISTRY__USERNAME="myuser"
export OPENCTI__DAEMON__REGISTRY__PASSWORD="mypassword"
export OPENCTI__DAEMON__REGISTRY__EMAIL="user@example.com"  # Optional
```

### Required fields

XTM Composer authenticates to the registry only when both of these fields are set:

- **username**: Registry username
- **password**: Registry password or token

### Optional fields

- **server**: Registry server (for example `registry.example.com`). It has no default value. When set, XTM Composer prepends it to every connector image name (see [Registry Prefix Resolution](#registry-prefix-resolution)). When not set, the image names are used as they are and pulled from the default registry of the container engine (Docker Hub for Docker). On Kubernetes, `server` is required when `username` and `password` are set: without it, XTM Composer fails at startup.
- **email**: User email, added to the credentials

---

## Kubernetes Secret Auto-Creation

When using the **Kubernetes orchestrator**, XTM Composer automatically creates an `imagePullSecret` at startup if `server`, `username` and `password` are configured. If `username` and `password` are set without `server`, XTM Composer fails at startup.

### Behavior

**With credentials configured:**

1. At startup, the orchestrator deletes the existing registry secret, if any
2. Creates a new secret with your credentials
3. Automatically attaches this secret to deployed connector pods

**Without credentials:**

- No secret is created
- You can manually create and configure your own secret if needed

### Secret Details

- **Name**: derived from the `server` value, converted to a valid Kubernetes name (for example, `registry.example.com` gives a name starting with `registry-example-com`)
- **Type**: `kubernetes.io/dockerconfigjson`
- **Lifecycle**: Recreated on each startup if credentials present

### Expected Startup Logs

At startup, look for the `Kubernetes registry secret created` message. On failure, XTM Composer logs `Kubernetes registry secret creation failed` with the error.

### Required Kubernetes Permissions

XTM Composer only creates and deletes secrets. The Role of the [installation guide](installation.md#production-environment-kubernetes) already includes this rule. If you use your own Role, add it:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: xtm-composer-role
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create", "delete"]
```

### Troubleshooting

**Secret creation fails:**

- Check that your ServiceAccount has the required RBAC permissions
- Verify credentials are correct
- Check startup logs for error messages

**Pods can't pull images:**

- Verify the secret exists: `kubectl get secrets --field-selector type=kubernetes.io/dockerconfigjson`
- Check secret is attached to pods: `kubectl describe pod <pod-name>`
- Ensure registry server is accessible from the cluster

---

## Registry Prefix Resolution

The Integration Manager automatically handles registry prefixes in image names:

- When `server` is set, it is always prepended to the image name of the connector, so your registry must host the images under the same name.
- When `server` is not set, the image name is used as it is.

Example:

```yaml
# Image without prefix
image: "opencti/connector-example:1.0.0"

# After resolution
image: "registry.example.com/opencti/connector-example:1.0.0"
```

See also: [Proxy Support](proxy-configuration.md)