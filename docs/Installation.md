# Manual installation

*Prerequisites*:

- NodeJS (>= 8.X)
- Grakn (>= 1.5)
- JAVA (== 8)

*Installation of dependencies (Ubuntu 18.04)*:
```bash
$ sudo apt-get install nodejs npm
```

*Download the application files*:
```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ wget https://github.com/LuatixHQ/opencti/releases/download/v0.1/opencti-release-0.1.tar.gz
$ tar xvfz opencti-release-0.1.tar.gz
```

*Install the main application and create the database schema*:
```bash
$ cd openex-app
$ composer install
$ php bin/console doctrine:schema:create
$ php bin/console app:db-init
```

During the database initialization, the administrator token will be displayed.

*Configure the worker*:
```bash
$ cd openex-worker/openex
```

*File openex.properties*:
```bash
# Openex
openex.api=http://url_of_the_application/api
openex.token=administrator_token
```

You have to configure the file *openex_email.properties* with your own parameters. The file *openex_ovh_sms.properties* is for using the [OVH API](https://www.ovh.com) to send SMS.

*Launch the worker*:
```bash
$ cd openex-worker/bin
$ ./start
```
