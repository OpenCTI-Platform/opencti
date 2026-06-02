# Automated import

Users can streamline the data ingestion process using various automated import capabilities. Each method proves beneficial in specific circumstances.

- [Connectors](external-connectors.md) act as bridges to retrieve data from diverse sources and format it for seamless ingestion into OpenCTI.
- [Streams enable](internal-streams.md) collaborative intelligence sharing across OpenCTI instances, fostering real-time updates and efficient data synchronization.
- [TAXII Feeds](taxii-feed.md) provide a standardized mechanism for ingesting threat intelligence data from TAXII servers or other OpenCTI instances.
- [TAXII Push](taxii-push.md) provide a standardized mechanism for ingesting STIX 2.1 formatted intelligence data by pushing the data into dedicated TAXII collections exposed by OpenCTI.
- [RSS Feeds](rss-feed.md) facilitate the import of items in report form from specified RSS feeds, offering a straightforward way to stay updated on relevant intelligence.
- [CSV Feeds](csv-feed.md) facilitate the ingestion of data exposed in the form of CSV files, offering a straightforward way to ingest any CSV feeds.
- [JSON Feeds](json-feed.md) facilitate the ingestion of data exposed in JSON format, offering a straightforward way to ingest any JSON feeds.

By leveraging these automated import functionalities, OpenCTI users can build a comprehensive, up-to-date threat intelligence database. The platform's adaptability and user-friendly configuration options ensure that intelligence workflows remain agile, scalable, and tailored to the unique needs of each organization.

## Connector behaviors

The behavior of each connector is defined by its development, determining the types of data it imports and its configuration options. This flexibility allows users to customize the import process to their specific needs, ensuring a seamless and personalized data integration experience.
The level of configuration granularity regarding the imported data type varies with each connector. Nevertheless, connectors empower users to specify the date from which they wish to fetch data. This capability is particularly useful during the initial activation of a connector, enabling the retrieval of historical data. Following this, the connector operates in real-time, continuously importing new data from the source.

## Stream / Push / Feed import behaviors

An ingestion manager runs periodically in background, and for each running feeds:
- fetches new data from the source. When data is paginated, fetches the next page
- compose a stix bundle for data and send it in queue to be processed by workers

!!! Note on timeline of data ingestion from Taxii feed, CSV feed, JSON feed and RSS feed.

    Depending on workers load, the data can take some time between the fetch from source and visibility in the platform.

Periodicity interval is configured with the manager with `ingestion_manager:interval`.
Feed can be configured to schedule data fetch on a longer period.

## URI deny list

Platform administrators can restrict which URIs are allowed for ingestion feeds (CSV, RSS, TAXII, and JSON) by configuring a deny list. When a user attempts to create or update an ingestion feed with a URI that matches a denied pattern, the platform rejects the request with an error.

This is useful for preventing ingestion from internal services, known-bad sources, or any other hosts that should not be accessed by the platform.

### Configuration

The deny list is configured via the `ingestion_manager:uri_deny_list` parameter. It accepts a JSON array of URI patterns.

**In the platform configuration file (`default.json` or environment-specific):**

```json
"ingestion_manager":{
  "uri_deny_list": [
    "internal-service.local",
    "*.corp.internal",
    "localhost:4200"
  ]
}
```

**Using environment variables:**

```bash
INGESTION_MANAGER__URI_DENY_LIST='["internal-service.local","*.corp.internal","localhost:4200"]'
```

### Supported patterns

| Pattern type   | Example          | Matches                                                                                          |
|:---------------|:-----------------|:-------------------------------------------------------------------------------------------------|
| Exact match    | `mydomain.com`   | Any URI with host `mydomain.com` (e.g. `https://mydomain.com/feed`)                              |
| Wildcard       | `*.mydomain.com` | Any subdomain of `mydomain.com` (e.g. `https://sub.mydomain.com/feed`) and `mydomain.com` itself |
| Host with port | `localhost:4200` | Only the specific host and port combination (e.g. `http://localhost:4200/data`)                  |

!!! note "Pattern matching details"

    - Matching is **case-insensitive**.
    - The deny list applies to all ingestion feed types: CSV, RSS, TAXII, and JSON.
    - The check is performed at feed creation, feed update (when the URI changes), and at fetch time.
    - Wildcard patterns (`*.domain.com`) match both subdomains and the base domain itself.


