# Prerequisites Ubuntu

Development stack require some base software that need to be installed.

## Docker or podman

Platform dependencies in development are deployed through container management, so you need to install a container stack.

We currently support docker and podman.

```bash
$ sudo apt-get install docker docker-compose curl
```

```bash
sudo apt-get -y install podman
```

As OpenCTI has a dependency to ElasticSearch, you have to set the *vm.max_map_count* before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sudo sysctl -w vm.max_map_count=262144
```

## NodeJS and yarn

The platform is developed on NodeJS technology. It requires Node.js 22.18.0 or later (the `engines` field of `package.json`), and the Docker image and the CI use Node.js 22.
The `nodejs` package of the Ubuntu archive can be older (Ubuntu 24.04 ships Node.js 18), so install Node.js 22 from [NodeSource](https://github.com/nodesource/distributions):

```bash
$ curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh
$ sudo -E bash nodesource_setup.sh
$ sudo apt-get install -y nodejs
```

The repository pins its Yarn version in the `packageManager` field of `package.json`, and corepack runs that version for you.
Please ensure Yarn v1 is not installed since it will conflict with corepack and recent version of Yarn.

```bash
$ sudo npm uninstall -g yarn
$ sudo npm install -g corepack
$ sudo corepack enable
```

## Python runtime

For worker and connectors, a python runtime is needed. Use Python 3.10, 3.11 or 3.12: the CI tests the Python client (pycti) with these versions.
The `venv` module creates the Python virtual environments used on the [platform development](platform.md) page.

The `node-calls-python` dependency is a native module compiled during `yarn install` (`re2` is also compiled when no prebuilt binary is available), so you also need a C++ toolchain and the Python headers.

```bash
$ sudo apt-get install python3 python3-pip python3-venv python3-dev build-essential
```

## Git and dev tool

- Install Git from apt

```bash
$ sudo apt-get install git-all
```

- Install your preferred IDE
    - Intellij community edition - https://www.jetbrains.com/idea/download/
    - VSCode - https://code.visualstudio.com/
