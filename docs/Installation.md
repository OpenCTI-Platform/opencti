# Manual installation

*Prerequisites*:

- NodeJS (>= 8)
- JAVA (== 8)
- Grakn (>= 1.5)
- Redis (>= 3.0)
- ElasticSearch (>= 6)
- RabbitMQ (>= 3.7)

*Installation of dependencies (Ubuntu 18.04)*:
```bash
$ sudo apt-get install nodejs npm redis-server rabbitmq-server
```

*Download the application files*:
```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ wget https://github.com/LuatixHQ/opencti/releases/download/v0.1/opencti-release-0.1.tar.gz
$ tar xvfz opencti-release-0.1.tar.gz
```

*Configure the application*:
```bash
$ cd opencti-release-0.1
$ cp config/default.json config/production.json
```

Change the *config/production.json* file according to your configuration of Grakn, Redis, ElasticSearch, RabbitMQ and keys.

*Create the database schema and initial data*:
```bash
$ npm run schema
$ npm run migrate
```

*Start the application*:
```bash
$ node dist/server.js
```
