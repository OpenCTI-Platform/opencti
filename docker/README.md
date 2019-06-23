# Docker installation

## Development
The technical stack needed to develop openCTI can be easily deployed with *docker-compose*.

Docker will run the following process :
* Grakn (Database) - *localhost/48555*
* Elastic search (Index and search) - *localhost/9200*
* Redis (Distribution cache for websocket events) - *localhost/6379*
* RabbitMQ (Message broker for background tasks) - *localhost/5672*

For you devenv you need to install by yourself
* Nodejs
* Yarn
* Python2
* Your favorite IDE

*Run*:
```bash
$ docker-compose -f ./docker-compose-dev.yml up -d
```

After 30 seconds you can start:
* opencti-graphql for the API

```bash
$ yarn install
$ yarn start
```

* opencti-front for the UI

```bash
$ yarn install
$ yarn start
```

* opencti-worker for the background taks

```bash
$ pip3 install -r requirements.txt
$ python3 worker_import.py & python3 worker_export.py
```

## Staging
OpenCTI could be deployed using the *docker-compose* command.

*Clone the repository*:
```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/LuatixHQ/opencti.git
$ cd opencti/docker
```

Before running the docker-compose command, please change the secret key of the application in the file *docker-compose.yml*
```bash
- APP__SECRET=ChangeMe
```

*Run*:
```bash
$ docker-compose up
```

You can now go to http://localhost:8080 and log in with username *admin@opencti.io* and password *admin*.
