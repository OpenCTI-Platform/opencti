# ENVIRONMENT SETUP (WINDOWS 10 BARE METAL)

This summary should give you a detailed setup description for initiating the OpenCTI setup environment necessary for developing on the OpenCTI platform, a client library, or the connectors using a Windows 10 development machine.

This page documents how to set up an "All-in-One" development environment for OpenCTI. Everything was done on a Windows 10 Laptop - Bare Metal (16 vCPU / 16Gb RAM) which contains:

- The OpenCTI project code base:
    - web frontend (nodejs / react)
        - `~/opencti/opencti-platform`
    - backend (nodejs / python)
        - `~/opencti/opencti-worker`
    - connectors (python)
        - `~/connectors`
    - python client
        - `~/client-python`
- docker-compose for the databases / broker
    - elasticsearch (and kibana)
    - redis
    - minio
    - rabbitmq

# EDITORIAL NOTE
Use of Windows as a development platform in not recommend - but is possible. The OpenCTI platform is distributed in Linux based platform containers, so Windows development is not necessarily in-line with the distribution model. You could encounter odd program behavior or difficulties developing against Windows. Windows is a very popular platform, so the instructions are provided to support that audience of developers. However, you would be better served developing on a native Linux based or MacOS based host platform.  
# PRE-CONFIGURATION TASKS

- Create a Development Folder
   - For our setup example, you will be using `~/Documents/Development` as your development folder.

- Set Environment Scripts
   - **environment.txt** - You will need to "mimic" what on a Linux platform the `/etc/environment` file performs. 
      - You will need to generate (10) Version 4 UUID using the following site:
https://www.uuidtools.com/generate/bulk

        Then, manually cut/paste each of the IDs below

        You can create an `~/Documents/Development/environment.txt` file that looks like:
        ```
        OPENCTI_ADMIN_EMAIL=admin@opencti.io
        OPENCTI_ADMIN_PASSWORD=CHANGEMEPLEASE
        OPENCTI_ADMIN_TOKEN=<UUID #1>
        OPENCTI_BASE_URL=http://localhost:8080
        SMTP_HOSTNAME=localhost
        ELASTIC_MEMORY_SIZE=4G
        MINIO_ROOT_USER=<UUID #2>
        MINIO_ROOT_PASSWORD=<UUID #3>
        RABBITMQ_DEFAULT_USER=guest
        RABBITMQ_DEFAULT_PASS=guest
        CONNECTOR_HISTORY_ID=<UUID #4>
        CONNECTOR_EXPORT_FILE_TXT_ID=<UUID #5>
        CONNECTOR_IMPORT_DOCUMENT_ID=<UUID #6>
        CONNECTOR_EXPORT_FILE_STIX_ID=<UUID #7>
        CONNECTOR_EXPORT_FILE_CSV_ID=<UUID #8>
        CONNECTOR_IMPORT_FILE_STIX_ID=<UUID #9>
        CONNECTOR_IMPORT_REPORT_ID=<UUID #10>
        DOCKER_IP=127.0.0.1
        TZ=America/New_York
        ```

  - **set_environment.sh** - You will need a script that you can use to set all of the OpenCTI environment variables with at launch time. This script will look like the following and use the `~/Documents/Development/environment.txt` file. You can save this file as: `~/Documents/Development/set_environment.sh`

    ```
    #!/bin/sh
    #
    # Configure the proper ENVARS to share to the GraphQL Server and NodeJS/React Front End. You must run this inside of git-bash on a Windows machine.
    #
    #
    # To use this:
    #  source ~/Documents/Development/set_environment.sh
    #
    export $(cat ~/Documents/Development/environment.txt | grep -v "#" | xargs)
    export NODE_OPTIONS=--max_old_space_size=8192
    export NODE_ENV=development
    echo "Development Environment Enabled"
    echo " - To start the development front end navigate to opencti/opencti-platform/opencti-graphql and run:"
    echo "       yarn serv --conf config/development.json "
    ```

# CONFIGURATION TASKS
   * Install OpenCTI Development Components on Windows Machine
     - Install Visual Studio Build Tools from - https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools
       - Check off Desktop Development with C++
       - Run install
     - Download GIT for Windows (64-bit Setup)- https://git-scm.com/download/win
        - Just use defaults on each screen
     - Install NodeJS from - https://nodejs.org/download/release/v16.20.0/node-v16.20.0-x64.msi
        - Select the option for installing Chocolatey on the Tools for Native Modules screen
            - Will do this install for you automatically - https://chocolatey.org/packages/visualstudio2019-workload-vctools
            - Includes Python 3.11.4
        - Shell out to CMD prompt as Administrator and install/run:
            - `pip3 install pywin32`
     - Configure Yarn (https://yarnpkg.com/getting-started/install)
        - Open CMD as Administrator and run the following command:
            - `corepack enable`
     - Install VSCode from - https://code.visualstudio.com/docs/?dv=win64  (You can use a different/your favorite IDE)
     - Docker Desktop from - https://docs.docker.com/desktop/install/windows-install/
       - Install new version of - https://docs.microsoft.com/windows/wsl/wsl2-kernel. This will require a reboot.
          - Shell out to CMD as Administrator and run the following series of commands:
            - `powershell`
            - `wsl --set-default-version 2`
            - Reboot computer and continue to next step       
       - Load Docker Application
          - **NOTE DOCKER LICENSE - You are agreeing to the licence for Non-commercial Open Source Project use. OpenCTI is Open Source and the version you would be possibly contributing to enhancing is the unpaid non-commercial/non-enterprise version. If you intention is different - please consult with your organization's legal/licensing department.**
       - **Leave Docker Desktop running**

   * Install OpenCTI Docker on Windows Machine
     - Make sure you have left Docker Desktop running from the previous step
     - Create a folder in Documents called "Development"
     - Clone Project from OpenCTI
        - Open a git-bash window as Administrator
        - `cd ~/Documents/Development`
        - `git clone https://github.com/OpenCTI-Platform/docker.git`
        - `cd docker`
      - Build Development Docker deployment for OpenCTI
        - Open a git-bash window as Administrator
        - From the `~/Documents/Development/docker` folder (i.e. `cd ~/Documents/Development/docker`)
           - `source  ~/Documents/Development/set_environment.sh`
           - `docker-compose -f ./docker-compose.dev.yml up -d`
           - This should result in 5/5 running items - but no connectors pulling in data
           - **Leave this running**
     - Clone Project from OpenCTI (you should really create a fork first and clone from that URL versus the OpenCTI main project)
        - Open a git-bash window as Administrator
        - `cd ~/Documents/Development`
        - `git clone https://github.com/OpenCTI-Platform/opencti.git`
        - `cd opencti`
      - Build Front-End Source Code
         - Open a git-bash window as Administrator
         - `source ~/Documents/Development/set_environment.sh`
         - `cd ~/Documents/Development/opencti/opencti-platform/opencti-front`
         - `yarn install`
         - `yarn build`
      - Build GraphQL Source Code and test running in development mode
         - Open git-bash as Administrator
         - `source ~/Documents/Development/set_environment.sh`
         - `cd ~/Documents/Development/opencti/opencti-platform/opencti-graphql`
         - You will need to setup a config/development.json file (only need to do this once)
            - `cp ./config/default.json ./config/development.json`
            - Edit the development.json file in a text editor. Update the following section:
            ```
                "admin": {
                  "email": "admin@opencti.io",
                  "password": "ChangeMe",
                  "token": "ChangeMe"
                }
            ``` 
            The Token will be the OPENCTI_ADMIN_TOKEN from above in the `~/Documents/Development/environment.txt`. The password can be set to something like CHANGEMEPLEASE. Example:
            ```
                "admin": {
                  "email": "admin@opencti.io",
                  "password": "CHANGEMEPLEASE",
                  "token": "40BF5910-AA14-43D9-AE7F-7BAF3EB8F663"
                }
            ```
         - `yarn install`
         - `yarn install:python`
         - `yarn build`
         - `yarn serv --conf config/development.json`
           - If firewall popup happens - Check Firewall Local Networks and Public Networks and then Allow 


# LOGIN TO THE DEVELOPMENT DEPLOYMENT

## Minified Version
- After the above steps, starting the Docker Container, and running the `yarn serv --conf config/development.json` you should be able to open a browser and navigate to: http://localhost:4000/
  - Username: `admin@opencti.io`
  - Password: `CHANGEMEPLEASE`

## Non-Minified Version
- The non-minified version required that you started the Minified version - first.
- Then - If you would like the run the Front-End - non-minified to help with debugging you need to:
  - `cd ~/Documents/Development/opencti/opencti-platform/opencti-front`
  - `yarn start`
  - After the above steps you should be able to open a browser and navigate to: http://localhost:3000/
    - Username: `admin@opencti.io`
    - Password: `CHANGEMEPLEASE`
  - This instance of the tool will NOT be minified and can help with debugging of code changes.

# DAILY DEVELOPMENT STARTUP/ACTIVITIES
- Start Docker Desktop App and your OpenCTI Container.
- Open git-bash as Administrator
- `source ~/Documents/Development/set_environment.sh`
- `cd ~/Documents/Development/opencti/opencti-platform/opencti-graphql`
- `yarn serv --conf config/development.json`
  - If firewall popup happens - Check Firewall Local Networks and Public Networks and then Allow 

It will now be running on port 4000. If you change code in the opencti-front folder, you need to:
  - `yarn lint`
  - `yarn check-ts`
  - `yarn build`
  - Changes will be loaded into the running opencti-graphql service.

If you change code in the opencti-graphql folder, you need to:
  - `yarn lint`
  - `yarn check-ts`
  - `yarn build`
  - You will then need to stop your running invocation of `yarn serv --conf config/development.json` and relaunch it.
