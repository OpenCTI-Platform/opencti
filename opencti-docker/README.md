OpenCTI could be deployed using the *docker-compose* command.

## Clone the repository

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/OpenCTI-Platform/opencti.git
$ cd opencti/opencti-docker
```

### Configure the environement

Before running the docker-compose command, please change the admin token (we advise you to generate a [uuidv4](https://www.uuidgenerator.net/) for it) and password of the application in the file `docker-compose.yml`:

```bash
- APP__ADMIN__PASSWORD=admin
- APP__ADMIN__TOKEN=ChangeMe
```

And the change the variable `OPENCTI_TOKEN` (for `worker-import` and `worker-export`) according to the value of `APP__ADMIN__TOKEN`

```bash
- OPENCTI_TOKEN=ChangeMe
```

As OpenCTI has a dependency to ElasticSearch, you have to set the `vm.max_map_count` before running the containers, as mentionned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sysctl -w vm.max_map_count=262144 
```

## Run

```bash
$ docker-compose up
```

You can now go to http://localhost:8080 and log in with username `admin@opencti.io` and password `admin`.

## Data persistence

If you wish your OpenCTI data to be persistent in production, you should be aware of the  `volumes` section for both `Grakn` and `ElasticSearch` services in the `docker-compose.yml`.