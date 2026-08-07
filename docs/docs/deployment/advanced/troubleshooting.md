# Troubleshooting

This page aims to explain the typical errors you can have with your OpenCTI platform.

## Finding the relevant logs

It is highly recommended to monitor the error logs of the platforms, workers and connectors. All the components have log outputs in an understandable JSON format. If necessary, it is always possible to increase the log level. In production, it is recommended to have the log level set to `error`.

### Platform

Here are some useful parameters for platform logging:

```yaml
- APP__APP_LOGS__LOGS_LEVEL=[error|warning|info|debug]
- APP__APP_LOGS__LOGS_CONSOLE=true # Output in the container console
```

### Connectors

All connectors support the same set of parameters to manage the log level and outputs:

```yaml
- OPENCTI_JSON_LOGGING=true # Enable / disable JSON logging
- CONNECTOR_LOG_LEVEL=info=[error|warning|info|debug]
```

### Workers

The workers can have more or less verbose outputs:

```yaml
- OPENCTI_JSON_LOGGING=true # Enable / disable JSON logging
- WORKER_LOG_LEVEL=[error|warning|info|debug]
```

## ElasticSearch / OpenSearch data

!!! tip "Kibana / OpenSearch dashboard"

    In case you need to troubleshoot the OpenCTI knowledge data, we recommend to install Kibana or OpenSearch dashboard.



## Common errors

### Ingestion technical errors

!!! warning "Missing reference to handle creation"
    
    After 5 retries, if an element required to create another element is missing, the platform raises an exception. It usually comes from a connector that generates inconsistent STIX 2.1 bundles.


!!! warning "Cant upsert entity. Too many entities resolved"
    
    OpenCTI received an entity which is matching too many other entities in the platform. In this condition we cannot take a decision. We need to dig into the data bundle to identify why it matches too much entities and fix the data in the bundle / or the platform according to what you expect.


!!! warning "Execution timeout, too many concurrent call on the same entities"
    
	The platform supports multi workers and multiple parallel creation but different parameters can lead to some locking timeout in the execution. 

	* Throughput capacity of your ElasticSearch
	* Number of workers started at the same time
	* Dependencies between data
	* Merging capacity of OpenCTI

	If you have this kind of error, limit the number of workers deployed. Try to find the right balance of the number of workers, connectors and elasticsearch sizing.


### Ingestion functional errors

!!! warning "Indicator of type yara is not correctly formatted"
    
    OpenCTI check the validity of the indicator rule.

!!! warning "Observable of type IPv4-Addr is not correctly formatted"
    
    OpenCTI check the validity of the observable value.

### Dependencies errors

!!! warning "TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark..."
    
    Disk full, no space left on the device for ElasticSearch.

## Redis state management

OpenCTI stores critical runtime state in Redis, not only a disposable cache. Among other things, Redis holds:

* **Work tracking** — every connector ingestion job is tracked through work identifiers stored in Redis.
* **Distributed locks** — used to prevent duplicate entity creation during concurrent ingestion.
* **Stream coordination** — live stream and TAXII data-sharing positions.
* **Caching and session data** — API caching and user sessions.

!!! warning "Never run `FLUSHDB` or `FLUSHALL` on a live OpenCTI Redis"

    Flushing Redis destroys all of the state above. RabbitMQ queues, however, live in a separate system and **survive the flush**, which leaves bundles in the queue that reference work identifiers that no longer exist. Workers then dequeue those bundles, try to update their (now missing) work, and the platform raises `WORK_NOT_ALIVE` errors (`Work is no longer alive, no request can be done within the context of this work`). The result is ingest nodes burning CPU on retries while ElasticSearch stays idle and the queue backlog never drains.

### Symptoms of a flushed Redis

* `WORK_NOT_ALIVE` errors in the platform and worker logs.
* A growing RabbitMQ backlog that does not drain despite healthy infrastructure.
* ElasticSearch idle (no write rejections, no active merges) while the queue is large.
* Uneven ingest-node CPU — some workers hot in retry loops, others idle.
* Works stuck "In progress" with no completed operations.

### Recovery after a flush

If `FLUSHDB`/`FLUSHALL` has already been run, the orphaned queues must be cleared so connectors can recreate fresh work:

1. Purge the stale connector queues in RabbitMQ (the bundles referencing dead work identifiers).
2. Reset the affected connector state in OpenCTI.
3. Restart the ingest/worker pods.
4. Restart the platform pods.
5. Restart the connectors so they create new work identifiers.
6. Monitor the logs until the `WORK_NOT_ALIVE` errors stop.

### Safe alternatives when Redis memory is high

High Redis memory is usually a symptom (often a connector queue backlog), so address the cause instead of flushing:

* Identify what is consuming memory with `redis-cli --bigkeys`.
* Purge the specific **RabbitMQ** connector queues that are backed up — not Redis.
* Trim the event stream if stream growth is the issue.
* Delete a specific stuck lock key surgically rather than flushing the whole database.

### Recommended Redis configuration

* Set `maxmemory` explicitly rather than relying on the container being OOM-killed.
* Use `maxmemory-policy noeviction` so Redis never silently evicts the critical state listed above (a write will fail loudly instead of corrupting platform state).
* Monitor memory usage, blocked clients and the slowlog.
