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

When upgrading the platform, you have to replace all files, install the dependencies of the new version and restart the platform, the database migrations will be done automatically.

From the `opencti/opencti-platform/opencti-graphql` folder (`yarn build` also installs the Python modules in `opencti/.venv`):

```bash
$ yarn install
$ yarn build
$ yarn serv
```

From the `opencti/opencti-worker/src` folder, for each worker (`uv run` installs its Python modules in `opencti/.venv`):

```bash
$ uv run --locked worker.py
```

The platform loads its Python modules from `app:python_execution_venv`. If your `config/production.json` sets it, it must be `../../.venv/site-packages`, the virtual environment created by `yarn build`; at startup, the platform logs a warning when this path does not exist.
