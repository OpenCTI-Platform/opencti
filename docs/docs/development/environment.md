# Environment setup

This summary should give you a detailed setup description for initiating the OpenCTI setup environment necessary for developing on the OpenCTI platform, a client library or the connectors.

This page document how to setting up an "All-in-One" development ****environment for OpenCTI. Everything was done on a virtual machine (Virtualbox VM - 16 vCPU / 20Gb RAM) which contains:

- the OpenCTI project code base:
    - web frontend (nodejs / react)
        - `~/opencti/opencti-platform`
    - backend (nodejs / python)
        - `~/opencti/opencti-worker`
    - connectors (python)
        - `~/connectors`
    - python client
        - `~/client-python`
- docker-compose for the databases / broker
    - elasticsearch (and kibana)
    - redis
    - minio
    - rabbitmq

# Prerequisites

## Installation of dependencies (Ubuntu 20.04)

If you are on a version of Debian/Ubuntu prior to 20, please refer to this [GIthub issue](https://github.com/OpenCTI-Platform/opencti/issues/413).

```bash
$ sudo apt-get install docker docker-compose curl nodejs python3 python3-pip
$ sudo curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
$ sudo echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
$ sudo apt-get update && sudo apt-get install yarn
```

## Docker stack

As OpenCTI has a dependency to ElasticSearch, you have to set the *vm.max_map_count* before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sudo sysctl -w vm.max_map_count=262144
```

Clone the latest version of the dev docker compose and start

```bash
$ git clone https://github.com/OpenCTI-Platform/docker.git
$ cd docker
$ docker-compose -f ./docker-compose.dev.yml up -d
```

# Clone the project

Depending on the part of OpenCTI to which you want to contribute, fork and clone the appropriate git repository or just clone repos

- [https://github.com/OpenCTI-Platform/opencti/](https://github.com/OpenCTI-Platform/opencti/) - frontend / backend
- [https://github.com/OpenCTI-Platform/connectors](https://github.com/OpenCTI-Platform/connectors) - connectors
- [https://github.com/OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker) - docker stack
- [https://github.com/OpenCTI-Platform/client-python/](https://github.com/OpenCTI-Platform/client-python/) - python client

Example with the `opencti` repository:

```bash
git clone git@github.com:YOUR-USERNAME/opencti.git
cd ~/opencti
git remote add upstream https://github.com/OpenCTI-Platform/opencti.git

cd
git clone https://github.com/opencti/connectors.git
git clone https://github.com/opencti/docker.git
git clone https://github.com/opencti/client-python.git
```

# Application dependencies

## Install the backend GraphQL API dependencies

The GraphQL API is developped in JS and with some python code. As it's an "all-in-one" installation, the python environment will be installed in a virtual environment.

```bash
cd ~/opencti/opencti-platform/opencti-graphql
python3 -m venv .venv --prompt "graphql"
source .venv/bin/activate
pip install --upgrade pip wheel setuptools
yarn install
yarn install:python 
deactivate
```

## Install the frontend dependencies and build it

```bash
cd ~/opencti/opencti-platform/opencti-front
yarn install
yarn build
# The resulting build is then copied to ../../opencti-graphql/public/
```

## Install the worker dependencies

```bash
cd ~/opencti/opencti-worker/src
python3 -m venv .venv --prompt "worker"
source .venv/bin/activate
pip3 install --upgrade pip wheel setuptools
pip3 install -r requirements.txt
deactivate
```

# Configure the stack

### Configure Docker

Create a config file which contains:

- the opencti admin user/pass
- user/pass for minio, rabbitmq
- an UUID for each connector

```bash
sudo apt install -y jq
cd ~/docker
(cat <<EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=CHANGEMEPLEASE
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_REPORT_ID=$(cat /proc/sys/kernel/random/uuid)
DOCKER_IP=$(ip -j a show dev docker0 |jq -r '.[0].addr_info[0].local')
EOF
) > .env

cd ~/docker 
# trick to export the .env 
export $(cat .env | grep -v "#" | xargs)

echo """admin username: ${OPENCTI_ADMIN_EMAIL}
admin password: ${OPENCTI_ADMIN_PASSWORD}
minio user : ${MINIO_ROOT_USER}
minio password : ${MINIO_ROOT_PASSWORD}"""
```

## Configure the backend (GraphQL API)

We use the credentials defined in `~/docker/.env` to update the configuration of the backend.

```bash
sudo apt install -y jq moreutils
cd ~/opencti/opencti-platform/opencti-graphql/config
jq '.app.admin.token = $newtoken' --arg newtoken ${OPENCTI_ADMIN_TOKEN} \
  default.json > development.json
jq '.app.admin.password = $newtoken' --arg newtoken ${OPENCTI_ADMIN_PASSWORD} \
  development.json | sponge development.json
jq '.minio.access_key = $newtoken' --arg newtoken ${MINIO_ROOT_USER} \
  development.json | sponge development.json
jq '.minio.secret_key = $newtoken' --arg newtoken ${MINIO_ROOT_PASSWORD} \
  development.json | sponge development.json

jq '.redis.hostname = $newtoken' --arg newtoken ${DOCKER_IP} \
  development.json | sponge development.json
jq '.rabbitmq.hostname = $newtoken' --arg newtoken ${DOCKER_IP} \
  development.json | sponge development.json
jq '.minio.hostname = $newtoken' --arg newtoken ${DOCKER_IP} \
  development.json | sponge development.json
jq '.elasticsearch.url = $newtoken' --arg newtoken "http://${DOCKER_IP}:9200" \
  development.json | sponge development.json
```

Skip this command if you have a SMTP server or if you install local SMTP (see "Local SMTP (Optionnal)") 

```bash
jq '.subscription_scheduler.enabled = $newtoken' --arg newtoken "false" \
  development.json | sponge development.json
```

### Configure the backend (worker)

```bash
cd ~/opencti/opencti-worker/src
sed "s/ChangeMe/${OPENCTI_ADMIN_TOKEN}/g" config.yml.sample > config.yml
```

# Start the stack !

## Start the database

```bash
cd ~/docker
#Start the stack in background
docker-compose -f ./docker-compose-dev.yml up -d

docker ps
#> CONTAINER ID   IMAGE                                                  COMMAND                  CREATED       STATUS                            PORTS                                                                                                                                                 NAMES
#> 11d6b3dfda99   redis:6.2.4                                            "docker-entrypoint.s…"   9 hours ago   Up 8 seconds                      0.0.0.0:6379->6379/tcp, :::6379->6379/tcp                                                                                                             opencti-dev-redis
#> e0dc9983e855   rabbitmq:3.8-management                                "docker-entrypoint.s…"   9 hours ago   Up 8 seconds                      4369/tcp, 5671/tcp, 0.0.0.0:5672->5672/tcp, :::5672->5672/tcp, 15671/tcp, 15691-15692/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp, :::15672->15672/tcp   opencti-dev-rabbitmq
#> 19a620bc0b0e   docker.elastic.co/kibana/kibana:7.13.1                 "/bin/tini -- /usr/l…"   9 hours ago   Up 8 seconds                      0.0.0.0:5601->5601/tcp, :::5601->5601/tcp                                                                                                             opencti-dev-kibana
#> 024f3be652e2   minio/minio:RELEASE.2021-06-14T01-29-23Z               "/usr/bin/docker-ent…"   9 hours ago   Up 8 seconds (health: starting)   0.0.0.0:9000->9000/tcp, :::9000->9000/tcp                                                                                                             opencti-dev-minio
#> 4e84dcabb42e   docker.elastic.co/elasticsearch/elasticsearch:7.13.1   "/bin/tini -- /usr/l…"   9 hours ago   Up 8 seconds                      0.0.0.0:9200->9200/tcp, :::9200->9200/tcp, 0.0.0.0:9300->9300/tcp, :::9300->9300/tcp                                                                  opencti-dev-elasticsearch

docker logs opencti-dev-redis
#> 1:C 11 Aug 2021 21:01:32.800 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
#> 1:C 11 Aug 2021 21:01:32.800 # Redis version=6.2.4, bits=64, commit=00000000, modified=0, pid=1, just started
#> ...
```

## Start the frontend

```bash
cd ~/opencti/opencti-platform/opencti-graphql
source .venv/bin/activate
#yarn start
export NODE_OPTIONS=--max_old_space_size=8192
export NODE_ENV=development
yarn serv --conf config/development.json
```

The first execution will create and migrate the schema.

## Start the worker backend

```bash
cd ~/opencti/opencti-worker/src
source .venv/bin/activate
python worker.py
```

The web UI should be accessible on [http://127.0.0.1:4000](http://127.0.0.1:4000) 

# Build for production use

## Build the application

```bash
$ cd opencti-frontend
$ yarn build
$ cd ../opencti-graphql
$ yarn build
```

## Start the production package

```bash
$ yarn serv
```

# Tips

### Update all repositories

```bash
cd ~/docker
git fetch upstream
git merge upstream/master
git push origin master

cd ~/opencti/
git fetch upstream
git merge upstream/master
git push origin master

cd ~/client-python
git fetch upstream
git merge upstream/master
git push origin master

cd ~/connectors
git fetch upstream
git merge upstream/master
git push origin master

# the hard way
git fetch upstream
git checkout master
git reset --hard upstream/master  
git push origin master --force

```

### Working on the latest stable version (tag)

```bash
cd ~/opencti
LATEST_TAG=$(git describe --abbrev=0 --tags)
echo "Working on version ${LATEST_TAG}"
git checkout tags/${LATEST_TAG} -b ${LATEST_TAG}-branch

cd ~/client-python && git checkout tags/${LATEST_TAG} -b ${LATEST_TAG}-branch
cd ~/connectors && git checkout tags/${LATEST_TAG} -b ${LATEST_TAG}-branch
cd ~/docker && git checkout tags/${LATEST_TAG} -b ${LATEST_TAG}-branch

```

### Testing a connector in the docker stack

put the conf of the connector in a separate file:

```bash
docker-compose -f ./docker-compose-dev.yml -f ./docker-compose-connectors.yml up
```

### Other docker commands
