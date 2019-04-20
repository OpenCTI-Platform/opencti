# Development installation

### Development start

*Prerequisites*:

- Node.JS (>= 10)
- Python (>= 3)
- Grakn (>= 1.5)
- Redis (>= 3.0)
- ElasticSearch (>= 6)
- RabbitMQ (>= 3.7)

*Installation of dependencies (Ubuntu 18.04)*:
```bash
$ sudo apt-get install nodejs python3 python3-pip
$ sudo curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
$ sudo echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
$ sudo apt-get update && sudo apt-get install yarn
```

*Download the application files*:
```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/Luatix/opencti.git
$ cd opencti
```

*Install the API dependencies*:
```bash
$ cd opencti-graphql
$ yarn install
```

*Configure the API*:
```bash
$ cp config/default.json config/development.json
```

Change the *config/development.json* file according to your configuration of Grakn, Redis, ElasticSearch, RabbitMQ and keys.

*Create the database schema and initial data*:
```bash
$ yarn schema
$ yarn migrate
```

*Install the frontend dependencies*:
```bash
$ cd ../opencti-front
$ yarn install
```

*Start the application*:
```bash
$ cd opencti-graphql
$ yarn start &
$ cd opencti-frontend
$ yarn start
```

The default username is *admin@opencti.io* and the password is *admin*. Login and get the administrator token in your profile.

*Configure the worker*:
```bash
$ cd worker
$ cp config.yml.sample config.yml
```

Change the *config.yml* file according to your OpenCTI token, ElasticSearch, Grakn and RabbitMQ configuration.

*Start the workers*:
```bash
$ python3 worker_export.py &
$ python3 worker_import.py &
```

### Build for production use

*Build the application*:
```bash
$ cd opencti-frontend
$ yarn build
$ cd ../opencti-graphql
$ yarn build
```

*Start the production package*:
```bash
$ yarn serv
```
