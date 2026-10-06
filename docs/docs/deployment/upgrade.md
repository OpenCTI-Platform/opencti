# Upgrade

Depending on your [installation mode](installation.md), upgrade path may change.

!!! note "Migrations"
    
    The platform is taking care of all necessary underlying migrations in the databases if any. You can upgrade OpenCTI from any version to the latest one, including skipping multiple major releases.

## Using Docker

Before applying this procedure, please update your `docker-compose.yml` file with the new version number of container images.

### For single node Docker

```bash
$ sudo docker-compose stop
$ sudo docker-compose pull
$ sudo docker-compose up -d
```

### For Docker swarm

For each of services, you have to run the following command:

```bash
$ sudo docker service update --force service_name
```

## Manual installation

When upgrading the platform, you have to replace all files and restart the platform, the database migrations will be done automatically:

```bash
$ yarn serv
```

## Known issues

### `User already exists` crash loop after upgrading a legacy platform

!!! warning "Symptom"

    After upgrading an older platform to 7.x, the platform crash-loops on boot during admin initialization and never becomes available. The logs show:

    ```
    FunctionalError: User already exists
    ```

**Cause**

On boot, the platform resolves the admin account by its hardcoded identifier `OPENCTI_ADMIN_UUID` (`88ec0c6a-13ce-5e39-b486-354fe4a7084f`). On deployments where the admin account was created before this identifier became deterministic, the stored admin document has a **random** `internal_id` that does not match `OPENCTI_ADMIN_UUID`. As a result the admin lookup returns nothing, initialization falls into the *create* path, and creating the account collides with the existing admin on `user_email` — which raises `User already exists` and aborts startup.

This can affect any deployment carrying a sufficiently old admin account forward across the 7.x upgrade.

**How to confirm**

Look up the admin account by the email configured in `APP__ADMIN__EMAIL` and compare its stored `internal_id` with `OPENCTI_ADMIN_UUID` (`88ec0c6a-13ce-5e39-b486-354fe4a7084f`). If they differ, you are hitting this issue.

**Remediation**

The reliable fix is to reconcile the existing admin account so its identity matches `OPENCTI_ADMIN_UUID`, which lets the initialization take the *patch* path on the next boot. Avoid working around the crash by setting a different `APP__ADMIN__EMAIL`: that creates a second admin and leaves the legacy admin orphaned while it still owns historical objects. Because reconciling the identity is a data operation, take a backup first and reach out on the [Slack community](https://community.filigran.io) if you need guidance for your deployment.

!!! note "`APP__ADMIN__EXTERNALLY_MANAGED`"

    Setting `APP__ADMIN__EXTERNALLY_MANAGED=true` (`app:admin:externally_managed`) forces the admin `account_status` to `Locked` on every boot. This is the recommended posture for SSO-primary deployments that do not want a usable local admin login.
