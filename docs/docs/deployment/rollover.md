# Indices and rollover policies

## Introduction

ElasticSearch and OpenSearch both support rollover on indices. OpenCTI has been designed to be able to use aliases for indices and so support very well index lifeycle policies.

Thus, by default OpenCTI initialized indices with a suffix `-00001` and use wildcard to query indices. When rollover policies are implemented, indices are splitted to keep a reasonable volume of data in shards.

![Indices](assets/indices.png)

## ElasticSearch configuration

### Indices

We advise to put a rollover policy on all indices used by OpenCTI, here is the list:

* `opencti_history`
* `opencti_inferred_entities`
* `opencti_inferred_relationships`
* `opencti_internal_objects`
* `opencti_internal_relationships`
* `opencti_stix_core_relationships`
* `opencti_stix_cyber_observable_relationships`
* `opencti_stix_cyber_observables`
* `opencti_stix_domain_objects`
* `opencti_stix_meta_objects`

For your information, the indices which can grow rapidly are:

* Index `stix_meta_relationships`: it contains all the nested relationships between objects and labels / marking definitions / external references / authors, etc.
* Index `opencti_history`: it contains the history log of all objects in the platform.
* Index `stix_cyber_observables`: it contains all observables stored in the platform.
* Index `stix_core_relationships`: it contains all main STIX relationships stored in the platform.

### Licecycle policy

Here is n example of policy:

* Maximum primary shard size: `50 GB`
* Maximum docs in the primary shard: `25,000,000`
* Maximum age: `365 days`
* Maximum documents: `50,000,000`

![Rollover](assets/rollover.png)

Then, apply this policy automatically to all `opencti_*` indices.

!!! note "Rollover documentation"
    
    To have more details about automatic rollover and lifecycle policies, please read the [official ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-rollover.html).