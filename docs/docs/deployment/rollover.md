# Indices and rollover policies

!!! note "Default rollover policies"

    Since OpenCTI 5.9.0, rollover policies are automatically created when the platform is initialized for the first time. If your platform has been initialized using an older version of OpenCTI or if you would like to understand (and customize) rollover policies please read the following documentation.

## Introduction

ElasticSearch and OpenSearch both support rollover on indices. OpenCTI has been designed to be able to use aliases for indices and so support very well index lifeycle policies. Thus, by default OpenCTI initialized indices with a suffix `-00001` and use wildcard to query indices. When rollover policies are implemented (default starting OCTI 5.9.X if you initialized your platform at this version), indices are splitted to keep a reasonable volume of data in shards.

![Indices](assets/indices.png)

## ElasticSearch configuration

### Indices

By default, a rollover policy is applied on all indices used by OpenCTI.

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
* `opencti_stix_meta_relationships`

For your information, the indices which can grow rapidly are:

* Index `opencti_stix_meta_relationships`: it contains all the nested relationships between objects and labels / marking definitions / external references / authors, etc.
* Index `opencti_history`: it contains the history log of all objects in the platform.
* Index `opencti_stix_cyber_observables`: it contains all observables stored in the platform.
* Index `opencti_stix_core_relationships`: it contains all main STIX relationships stored in the platform.

### Default implemented licecycle policy

Here is the recommended policy (initialized starting 5.9.X):

* Maximum primary shard size: `50 GB`
* Maximum age: `365 days`
* Maximum documents: `75,000,000`

### Applying rollover policies on existing indices

!!! warning "Procedure information"
    
    Please read the following only if your platform has been initialized before 5.9.0, otherwise lifecycle policies has been created (but you can still cutomize them).

Unfortunately, to be able to implement rollover policies on ElasticSearch / OpenSearch indices, it will be needed to re-index all the data in new indices using ElasticSearch capabilities.

#### Shutdown

First step is to shutdown your OpenCTI platform.

#### Change configuration

Then, in the [OpenCTI configuration](configuration.md), change the ElasticSearch / OpenSearch default prefix to `octi` (default is `opencti`).

#### Create the rollover policy

Create a rollover policy named `octi-ilm-policy` (in Kibana, `Management > Index Lifecycle Policies`):

* Maximum primary shard size: `50 GB`
* Maximum age: `365 days`
* Maximum documents: `75,000,000`

![ILM Policy](assets/ilm-policy.png)

#### Create index templates

In Kibana, clone the `opencti-index-template` to have one index template by OpenCTI index with the appropriate rollover policy, index pattern and rollover alias (in Kibana, `Management > Index Management > Index Templates`).

![Index template](assets/index-template.png)

Create the following index templates:

* `octi_history`
* `octi_inferred_entities`
* `octi_inferred_relationships`
* `octi_internal_objects`
* `octi_internal_relationships`
* `octi_stix_core_relationships`
* `octi_stix_cyber_observable_relationships`
* `octi_stix_cyber_observables`
* `octi_stix_domain_objects`
* `octi_stix_meta_objects`
* `octi_stix_meta_relationships`

Here is the overview of all templates (you should have something with `octi_` instead of `opencti_`).

![Index templates](assets/templates.png)

#### Apply rollover policy on all index templates

Then, going back in the index lifecycle policies screen, you can click on the "+" button of the `octi-ilm-policy` to `Add the policy to index template`, then add the policy to add previously created template with the proper "Alias for rollover index".

![Add policy to template](assets/add-policy.png)

#### Re-index all indices

Using the `reindex` API, re-index all indices one by one:

```
curl -X POST "localhost:9200/_reindex?pretty" -H 'Content-Type: application/json' -d'
{
  "source": {
    "index": "opencti_history-000001"
  },
  "dest": {
    "index": "octi_history-000001"
  }
}
'
```

You will see the rollover policy to be applied and the new indices are automatically rolled-over during reindexation.

#### Delete all old indices

Then just delete all indices with the prefix `opencti_`.

#### Start your platform

Start your platform, using the new indices.

!!! note "Rollover documentation"
    
    To have more details about automatic rollover and lifecycle policies, please read the [official ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-rollover.html).