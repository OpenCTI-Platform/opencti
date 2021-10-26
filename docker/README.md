# Prerequisites

Make sure you have the following installed:

1. [Docker](https://docs.docker.com/engine/install/)
1. [Docker Compose](https://docs.docker.com/compose/install/)


# Setup

## Build Docker Images

From within the `docker` folder, run the following:

```
docker-compose build --no-cache
```

## Environment

1. Duplicate the `env.example` file found in the `docker` folder and call it `.env`. 
1. Edit the `.env` file and alter the values for your given environment.

**_Note: Any local changes will require a new build, simply run the docker build command again._**


# Running

To bring up the entire stack, run:
  
```
docker-compose up -d
```

To follow the logs of the entire stack, run:
  
```
docker-compose logs -f
```

To follow the logs of a specific service, run:

```
docker-compose logs -f <service>
```

example:

```
docker-compose logs -f opencti
```


# Access

Once the containers are up and running, you can access the running resource via the following links.

OpenCTI Frontend: [http://localhost:8080](http://localhost:8080)

Apollo: [http://localhost:4000](http://localhost:4000)


# Stopping

To bring down the stack, run the following: `docker-compose down`

