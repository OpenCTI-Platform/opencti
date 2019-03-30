## Docker installation

OpenEx provides a script *build.sh* wich using the *docker-compose* command allowing you to deploy the application in docker containers.

*Clone the repository*:
```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/LuatixHQ/openex.git
$ cd openex/docker
```

Before building and running the docker, you have to configure the mailer properties in the folder *properties*:

*In the file properties/openex_email.properties*:
```bash
# Openex mailer
openex_email.enable=true
# Specific configuration
openex_email.attachment_uri=/files
openex_email.sender=emailsender@yourdomain.com
openex_email.transport=smtps_or_smtp
openex_email.host=smtp_server_address
openex_email.user=smtp_server_username
openex_email.password=smtp_server_password
```

*Run*:
```bash
$ ./run.sh
```

You can now go to http://localhost:8080 and log in with username *admin@openex.io* and password *admin*.
