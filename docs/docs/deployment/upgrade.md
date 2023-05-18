# Upgrade

Depending on your [installation mode](installation.md), upgrade path may change.

!!! note "Migrations"
    
    The platform is taking care of all necessary underlying migrations in the databases if any, you can upgrade OpenCTI from any version to the latest one, including skipping multiple major releases.

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
