# Development installation

*Prerequisites*:

- NodeJS (>= 8)
- JAVA (== 8)
- Grakn (>= 1.5)
- Redis (>= 3.0)

*Installation of dependencies (Ubuntu 18.04)*:
```bash
$ sudo apt-get install nodejs redis-server
$ sudo curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
$ sudo echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
$ sudo apt-get update && sudo apt-get install yarn
```

*Installation of the database (Grakn)*:
```bash
$ sudo apt-get install openjdk-8-jre
$ mkdir /your/path/to/grakn
$ cd /your/path/to/grakn
$ wget https://github.com/graknlabs/grakn/releases/download/v1.5.0/grakn-core-1.5.0.zip
$ unzip grakn-core-1.5.0.zip
$ cd grakn-core-1.5.0
$ ./grakn server start
```

More information on the Grakn installation and configuration can be found on the [official documentation](https://dev.grakn.ai/docs/running-grakn/install-and-run).

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

Change the *config/development.json* file according to your configuration of Grakn and Redis.

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
$ yarn start
$ cd opencti-frontend
$ yarn start
```
