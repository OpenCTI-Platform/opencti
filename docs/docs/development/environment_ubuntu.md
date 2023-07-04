# Prerequisites Ubuntu

Development stack require some base software that need to be installed.

## Docker or podman

Platform dependencies in development are deployed through container management, so you need to install a container stack.

We currently support docker and postman.

```bash
$ sudo apt-get install docker docker-compose curl
```

As OpenCTI has a dependency to ElasticSearch, you have to set the *vm.max_map_count* before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sudo sysctl -w vm.max_map_count=262144
```

## NodeJS and yarn

The platform is developed on nodejs technology, so you need to install node and the yarn package manager.

```bash
$ sudo apt-get install nodejs
$ sudo curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
$ sudo echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
$ sudo apt-get update && sudo apt-get install yarn
```

## Python runtime

For worker and connectors, a python runtime is needed.

```bash
$ sudo apt-get install python3 python3-pip
```

## Git and dev tool

- Install Git from apt

```bash
$ sudo apt-get install git-all
```

- Install your preferred IDE
    - Intellij community edition - https://www.jetbrains.com/idea/download/
    - VSCode - https://code.visualstudio.com/