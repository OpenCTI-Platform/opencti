# Troubleshooting

This page aims to explains the typical errors you can have with your OpenCTI platform.

## Finding the relevant logs

It is highly recommended to monitor the error logs of the platforms, workers and connectors. All the components have log outputs in an understandable JSON format. It necessary, it is always possible to increase the log level. In production, it is recommended to have the log level set to `error`.

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

## Common errors

### Ingestion technical errors

!!! warning "Missing reference to handle creation"
    
    After 5 retries, if an element required to create another element is missing, the platform raises an exception. It usually comes from a connector that generates inconsistent STIX 2.1 bundles.


!!! warning "Cant upsert entity. Too many entities resolved"
    
    OpenCTI received an entity which is matching too many other entities in the platform. In this condition we cannot take a decision. We need to dig into the data bundle to identify why he match too much entities and fix the data in the bundle / or the platform according to what you expect.


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
    
    OpenCTI check the validity of the oversable value.

### Dependencies errors

!!! warning "TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark..."
    
    Disk full, no space left on the device for ElasticSearch.
