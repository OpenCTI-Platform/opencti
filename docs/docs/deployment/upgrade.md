# Upgrade

Depending on your [installation mode](installation.md), upgrade path may change.

!!! note "Migrations"
    
    The platform is taking care of all necessary underlying migrations in the databases if any. You can upgrade OpenCTI from any version to the latest one, including skipping multiple major releases.

## Before you upgrade

1. Read the [breaking changes and migrations](breaking-changes.md) of every version between your current version and the target version. Some of them require an action on your side, such as a new mandatory configuration key or an upgrade of a dependency (Elasticsearch, OpenAEV, XTM Composer).
2. Back up your data: take a snapshot of the Elasticsearch / OpenSearch indices, copy the S3 bucket that stores the files (in the default Docker deployment, the `minio` service, which runs Silo), and keep a copy of your configuration files. The platform migrates its data at startup and only runs migrations forward: restoring this backup is the only way back to the previous version.

## Using Docker

Before applying this procedure, please update your `docker-compose.yml` file with the new version number of container images.

### For single node Docker

These commands use Docker Compose v2 (`docker compose`), installed with the `docker-compose-plugin` package as described in the [installation](installation.md#pre-requisites):

```bash
sudo docker compose stop
sudo docker compose pull
sudo docker compose up -d
```

### For Docker swarm

For each of services, you have to run the following command:

```bash
$ sudo docker service update --force service_name
```

## Manual installation

When upgrading the platform, you replace the application files with the ones of the new release and restart the platform. The database migrations run automatically at startup.

1. Stop the platform and the workers.
2. Keep a copy of your configuration files: `opencti/opencti-platform/opencti-graphql/config/production.json` and `opencti/worker/config.yml`.
3. [Download and extract the new release file](installation.md#download-the-application-files), replacing the previous files, then put your two configuration files back in place.
4. Install the dependencies and start the platform, from inside the `opencti/opencti-platform/opencti-graphql` folder, as for a [new installation](installation.md#start-the-application):

    ```bash
    yarn install
    TAG_VERSION={RELEASE_VERSION} yarn build
    yarn serv
    ```

    Replace `{RELEASE_VERSION}` with the version you install. `TAG_VERSION` makes `yarn build` fetch the connectors catalog of that release; without it, the build fetches the catalog of the connectors `master` branch.

    `yarn build` also reinstalls the Python modules of the platform (`src/python/requirements.txt`). They include the Python client (`pycti`), pinned to the version of the platform.

5. Update the Python modules of the worker. The release file does not contain the worker `requirements.txt`: download it from the release tag (replace `{RELEASE_VERSION}` with the version you install), then install it:

    ```bash
    cd /path/to/your/app/opencti/worker
    wget -O requirements.txt https://raw.githubusercontent.com/OpenCTI-Platform/opencti/{RELEASE_VERSION}/opencti-worker/requirements.txt
    pip3 install -r requirements.txt
    ```

6. Start the workers again:

    ```bash
    python3 worker.py &
    ```
