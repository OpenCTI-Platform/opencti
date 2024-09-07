# Indices and rollover policies

## Introduction

ElasticSearch and OpenSearch both support rollover on indices. OpenCTI has been designed to be able to use aliases for indices and so supports index lifecycle policies very well. Thus, by default OpenCTI initializes indices with a suffix of `-00001` and uses wildcards to query indices. When rollover policies are implemented (default starting OCTI 5.9.X if you initialized your platform at this version), indices are splitted to keep a reasonable volume of data in shards.

![Indices](assets/indices.png)


## OpenCTI Integration User Permissions in OpenSearch/ElasticSearch

- Index Permissions
    - **Patterns:** `opencti*` _(Dependent on the parameter [elasticsearch:index_prefix](configuration.md#elasticsearch) value)_
    - **Permissions:** `indices_all`

- Cluster Permissions
    - `cluster_composite_ops_ro`
    - `cluster_manage_index_templates`
    - `cluster:admin/ingest/pipeline/put`
    - `cluster:admin/opendistro/ism/policy/write`
    - `cluster:monitor/health`
    - `cluster:monitor/main`
    - `cluster:monitor/state`
    - `indices:admin/index_template/put`
    - `indices:data/read/scroll/clear`
    - `indices:data/read/scroll`
    - `indices:data/write/bulk`

!!! warning "About `indices:*` in _Cluster Permissions_"

    It is crucial to include `indices:*` permissions in **Cluster Permissions** for the proper functioning of the OpenCTI integration. Removing these, even if already present in **Index Permissions**, may result in startup issues for the OpenCTI Platform.

## ElasticSearch configuration

### Indices

By default, a rollover policy is applied on all indices used by OpenCTI.

* `opencti_deleted_objects`
* `opencti_files`
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
* `opencti_stix_sighting_relationships`

For your information, the indices which can grow rapidly are:

* Index `opencti_stix_meta_relationships`: it contains all the nested relationships between objects and labels / marking definitions / external references / authors, etc.
* Index `opencti_history`: it contains the history log of all objects in the platform.
* Index `opencti_stix_cyber_observables`: it contains all observables stored in the platform.
* Index `opencti_stix_core_relationships`: it contains all main STIX relationships stored in the platform.

### Default implemented lifecycle policy

Here is the recommended policy (for 1 shard per index) (initialized starting 5.9.X):

* Maximum primary shard size: `50 GB`
* Maximum documents: `75,000,000`

## Adapt platform initialized before the 6+ version

!!! warning "Procedure information"
    
    If your platform has been initialized before 5.9.0, your platform will be not configured to automatically managed the indices

Unfortunately, to be able to implement rollover policies on ElasticSearch / OpenSearch indices, it will be needed to:
- Upgrade your platform to the latest version
- Check that policy and templates are available after the migration
- split all the shards > 50Gb in new indices using ElasticSearch capabilities.
- Reconfigure the writing alias to the latest index and ensure that the policy is running correctly.

If you need any help for this migration, please join the slack community.

