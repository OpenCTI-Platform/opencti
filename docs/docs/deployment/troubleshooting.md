# Troubleshooting

This page aims to explains the typical errors you can have with your OpenCTI platform.

## Common errors

**Missing reference to handle creation**

After 5 retries, if an element required to create another element is missing, the platform raises an exception. It usually comes from a connector that generates inconsistent STIX 2.1 bundles.

**Cant upsert entity. Too many entities resolved**

OpenCTI received an entity which is matching too many other entities in the platform. In this condition we cannot take a decision. We need to dig into the data bundle to identify why he match too much entities and fix the data in the bundle / or the platform according to what you expect.

**Execution timeout, too many concurrent call on the same entities**

The platform supports multi workers and multiple parallel creation but different parameters can lead to some locking timeout in the execution. 

* Throughput capacity of your ElasticSearch
* Number of workers started at the same time
* Dependencies between data
* Merging capacity of OpenCTI

If you have this kind of error, limit the number of workers deployed. Try to find the right balance of the number of workers, connectors and elasticsearch sizing.

**Indicator of type yara is not correctly formatted**

OpenCTI check the validity of the indicator rule.

**Observable of type IPv4-Addr is not correctly formatted**

OpenCTI check the validity of the oversable value

**TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark, index has read-only-allow-delete block**

Disk full, no space left on the device for ElasticSearch.