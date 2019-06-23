# Docker installation

## Development
The technical stack needed to develop openCTI can be easily deployed with *docker-compose*.

*Run*:
```bash
$ docker-compose -f ./docker-compose-dev.yml up -d
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
