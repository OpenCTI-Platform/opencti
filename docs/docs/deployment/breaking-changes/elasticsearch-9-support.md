# Elasticsearch 9 support and search engine client detection

!!! info ""

    * **Introduced in**: `OpenCTI TBD`

## Description of changes

OpenCTI supports Elasticsearch 9 next to Elasticsearch 8 and OpenSearch, and picks the matching client by
itself. At startup, the platform calls `GET /` on `elasticsearch:url`, with its own TLS, credentials and proxy
settings, reads the version the server reports and creates the matching client:

| Server                   | Client used                                                                  |
|:-------------------------|:-----------------------------------------------------------------------------|
| Elasticsearch 8          | Elasticsearch 8.x                                                            |
| Elasticsearch 9          | Elasticsearch 9.x                                                            |
| Elasticsearch Serverless | Elasticsearch 9.x (the most recent client), recognised by its `serverless` build flavor |
| OpenSearch               | OpenSearch                                                                   |

Each Elasticsearch major needs its own client: the 9.x client stamps every request with an
`application/vnd.elasticsearch+json; compatible-with=9` content type, which an Elasticsearch 8 server rejects.

The `elasticsearch:engine_selector` (`ELASTICSEARCH__ENGINE_SELECTOR`) and `elasticsearch:engine_check`
(`ELASTICSEARCH__ENGINE_CHECK`) parameters are **removed**. A value still set is ignored, and the platform logs a
warning at startup. When the detection cannot work, for example behind a proxy that blocks `GET /` or with an
account that cannot read it, set `elasticsearch:engine_client` (`ELASTICSEARCH__ENGINE_CLIENT`) to
`elasticsearch8`, `elasticsearch9` or `opensearch`: the platform then uses that client without reading the
server version. Its default, `auto`, keeps the detection.

The detection works with every authentication method, including API keys (`elasticsearch:api_key`), which
previously required setting `engine_selector` to `elk`.

With AWS SigV4 authentication (`opensearch:region` set), the platform uses the OpenSearch client without
reading the server version, as before. `elasticsearch:engine_client` can then only be `auto` or `opensearch`.

The platform refuses to start, with an explicit message, when the server cannot be reached, rejects the
credentials, or answers `GET /` with an error or an unreadable response. With a forced client or AWS SigV4, it
still calls `GET /` at startup, only to check that the engine is up: it refuses to start when the engine does not
answer or answers with a server error (5xx), and accepts any other answer, a refusal of `GET /` included.

## Migration

Nothing to do: remove `elasticsearch:engine_selector` and `elasticsearch:engine_check` from your configuration
to get rid of the startup warning. Do not copy the value of `engine_selector` to `elasticsearch:engine_client`:
leave `engine_client` unset unless the detection fails, otherwise the client stays pinned when the cluster is
upgraded.

### Moving from Elasticsearch 8 to Elasticsearch 9

Before upgrading the cluster, make sure that:

* **Elasticsearch runs version 8.19 or later.** The upgrade path to Elasticsearch 9 starts from 8.19: an older
  8.x must be upgraded to 8.19 first.
* **No index was created under Elasticsearch 7.** Elasticsearch 9 only opens indices created by 8.x or later, and
  refuses to start while such an index remains, system indices included. `GET _migration/deprecations` and
  `GET _migration/system_features` report them, as does Kibana's Upgrade Assistant: they must be reindexed, or
  their system features migrated, while the cluster is still on 8.19.

Then upgrade the cluster following [Elastic's upgrade documentation](https://www.elastic.co/docs/deploy-manage/upgrade),
and restart OpenCTI: it detects the new version at startup and switches client. The indices are kept.

!!! warning "Take a snapshot first"

    OpenCTI keeps its data in Elasticsearch: the indices cannot be rebuilt from another store. Take a snapshot
    before upgrading. Once a node has started on Elasticsearch 9, the cluster cannot go back to
    Elasticsearch 8: restoring that snapshot on an 8.19 cluster is the only way back.
