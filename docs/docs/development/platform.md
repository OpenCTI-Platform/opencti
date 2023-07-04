# Platform development

## Introduction
This summary should give you a detailed setup description for initiating the OpenCTI setup environment 
necessary for developing on the OpenCTI platform, a client library or the connectors. 
This page document how to set up an "All-in-One" development **environment** for OpenCTI. 
The devenv will contain data of 3 different repositories:

- Platform: [https://github.com/OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti)
- Connectors: [https://github.com/OpenCTI-Platform/connectors](https://github.com/OpenCTI-Platform/connectors)
- Client python: [https://github.com/OpenCTI-Platform/client-python](https://github.com/OpenCTI-Platform/client-python)

### Platform
Contains the platform OpenCTI project code base:

- docker-compose (docker or podman) `~/opencti/opencti-platform/opencti-dev`
- Web frontend (nodejs / react) `~/opencti/opencti-platform/opencti-graphql`
- Backend (nodejs) `~/opencti/opencti-platform/opencti-frontend`
- Worker (nodejs / python) `~/opencti/opencti-worker`

### Connectors
Contains a lot of developed connectors, as a source of inspiration for your new connector.

### Client python
Contains the source code of the python library used in worker or connectors.

## Prerequisites

Some tools are needed before starting to develop. Please check [Ubuntu prerequisites](environment_ubuntu.md) or [Windows prerequisites](environment_windows.md)

## Clone the projects

Fork and clone the git repositories

- [https://github.com/OpenCTI-Platform/opencti/](https://github.com/OpenCTI-Platform/opencti/) - frontend / backend
- [https://github.com/OpenCTI-Platform/connectors](https://github.com/OpenCTI-Platform/connectors) - connectors
- [https://github.com/OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker) - docker stack
- [https://github.com/OpenCTI-Platform/client-python/](https://github.com/OpenCTI-Platform/client-python/) - python client

## Dependencies containers

In development dependencies are deployed trough containers.
A development compose file is available in `~/opencti/opencti-platform/opencti-dev`

```bash
cd ~/docker
#Start the stack in background
docker-compose -f ./docker-compose-dev.yml up -d
```

You have now all the dependencies of OpenCTI running and waiting for product to run.

## Backend / API

### Python virtual env

The GraphQL API is developed in JS and with some python code. 
As it's an "all-in-one" installation, the python environment will be installed in a virtual environment.

```bash
cd ~/opencti/opencti-platform/opencti-graphql
python3 -m venv .venv --prompt "graphql"
source .venv/bin/activate
pip install --upgrade pip wheel setuptools
yarn install
yarn install:python 
deactivate
```

### Development configuration

The API can be specifically configured with files depending on the starting profile.
By default, the default.json file is used and will be correctly configured for local usage **except for admin password**

So you need to create a development profile file. You can duplicate the default file and adapt if for you need.
```bash
cd ~/opencti/opencti-platform/opencti-graphql/config
cp default.json development.json
```

At minimum adapt the admin part for the password and token.
```json
    "admin": {
      "email": "admin@opencti.io",
      "password": "MyNewPassord",
      "token": "UUID generated with https://www.uuidgenerator.net"
    }
```

### Install / start

Before starting the backend you need to install the nodejs modules

```bash
cd ~/opencti/opencti-platform/opencti-graphql
yarn install
```

Then you can simply start the backend API with the yarn start command

```bash
cd ~/opencti/opencti-platform/opencti-graphql
yarn start
```

The platform will start logging some interesting information

```log
{"category":"APP","level":"info","message":"[OPENCTI] Starting platform","timestamp":"2023-07-02T16:37:10.984Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[OPENCTI] Checking dependencies statuses","timestamp":"2023-07-02T16:37:10.987Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[SEARCH] Elasticsearch (8.5.2) client selected / runtime sorting enabled","timestamp":"2023-07-02T16:37:11.014Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[CHECK] Search engine is alive","timestamp":"2023-07-02T16:37:11.015Z","version":"5.8.7"}
...
{"category":"APP","level":"info","message":"[INIT] Platform initialization done","timestamp":"2023-07-02T16:37:11.622Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[OPENCTI] API ready on port 4000","timestamp":"2023-07-02T16:37:12.382Z","version":"5.8.7"}
```

If you want to start on another profile you can use the -e parameter.
For example here to use the profile.json configuration file.

```bash
yarn start -e profile
```
### Code check

Before pushing your code you need to validate the syntax and ensure the testing will be validated.

#### For validation

`yarn lint`

`yarn check-ts`

#### For testing

For starting the test you will need to create a test.json file.
You can use the same dependencies by only adapting all prefix for all dependencies.

`yarn test:dev`

## Frontend

### Install / start

Before starting the backend you need to install the nodejs modules

```bash
cd ~/opencti/opencti-platform/opencti-front
yarn install
```

Then you can simply start the frontend with the yarn start command

```bash
cd ~/opencti/opencti-platform/opencti-front
yarn start
```

The frontend will start with some interesting information

```log
[INFO] [default] compiling...
[INFO] [default] compiled documents: 1592 reader, 1072 normalization, 1596 operation text
[INFO] Compilation completed.
[INFO] Done.
[HPM] Proxy created: /stream  -> http://localhost:4000
[HPM] Proxy created: /storage  -> http://localhost:4000
[HPM] Proxy created: /taxii2  -> http://localhost:4000
[HPM] Proxy created: /feeds  -> http://localhost:4000
[HPM] Proxy created: /graphql  -> http://localhost:4000
[HPM] Proxy created: /auth/**  -> http://localhost:4000
[HPM] Proxy created: /static/flags/**  -> http://localhost:4000
```

The web UI should be accessible on [http://127.0.0.1:4000](http://127.0.0.1:4000)

### Code check

Before pushing your code you need to validate the syntax and ensure the testing will be validated.

#### For validation

`yarn lint`

`yarn check-ts`

#### For testing

`yarn test`

## Worker

Running a worker is required when you want to develop on the ingestion or import/export connectors.

### Python virtual env

```bash
cd ~/opencti/opencti-worker/src
python3 -m venv .venv --prompt "worker"
source .venv/bin/activate
pip3 install --upgrade pip wheel setuptools
pip3 install -r requirements.txt
deactivate
```

### Install / start

```bash
cd ~/opencti/opencti-worker/src
source .venv/bin/activate
python worker.py
```

## Connectors

For connectors development, please take a look to [Connectors](connectors.md) development dedicated page.

## Production build

Based on development source you can build the package for production.
This package will be minified and optimized with esbuild.

```bash
$ cd opencti-frontend
$ yarn build
$ cd ../opencti-graphql
$ yarn build
```

After the build you can start the production build with yarn serv.
**This build will use the production.json configuration file**

```bash
$ cd ../opencti-graphql
$ yarn serv
```