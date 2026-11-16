# Feeds advanced configuration

Some configuration can be done with environment variables or in the platform configuration file to fine tune feeds ingestion.
This page lists the available configuration parameters.

## URI deny list

Platform administrators can restrict which URIs are allowed for ingestion feeds (CSV, RSS, TAXII, and JSON) by configuring a deny list. When a user attempts to create or update an ingestion feed with a URI that matches a denied pattern, the platform rejects the request with an error.

This is useful for preventing ingestion from internal services, known-bad sources, or any other hosts that should not be accessed by the platform.

### Configuration

The deny list is configured via the `app:uri_deny_list` parameter. It accepts a JSON array of URI patterns.

**Default value**: [] (no deny list)

**In the platform configuration file (`default.json` or environment-specific):**

```json
"app": {
  "uri_deny_list": [
    "internal-service.local",
    "*.corp.internal",
    "localhost:4200"
  ]
}
```

**Using environment variables:**

```bash
APP__URI_DENY_LIST='["internal-service.local","*.corp.internal","localhost:4200"]'
```

### Supported patterns

* Exact match: Deny any URI with a specific host (e.g. `mydomain.com`).
* Wildcard: Deny any URI with a host that matches a wildcard pattern (e.g. `*.mydomain.com`).
* Host with port: Deny any URI with a specific host and port combination (e.g `localhost:4200`).

!!! note "Pattern matching details"

    - Matching is **case-insensitive**.
    - The deny list applies to all ingestion feed types: CSV, RSS, TAXII, and JSON.
    - The check is performed at feed creation and feed update (when the URI changes).
    - Wildcard patterns (`*.domain.com`) match both subdomains and the base domain itself.

## Ingestion manager interval

The ingestion manager checks every running feed (TAXII, RSS, CSV and JSON) at a fixed interval, set by the `ingestion_manager:interval` parameter in milliseconds. At each check, a feed fetches data only once its schedule period, and the minimum interval of its feed type if any, have elapsed, and only when the data from its previous run has left its queue. While messages are still waiting in the queue, the feed is shown as buffering and skips the check.

**Default value**: 30000 (30 seconds)

**In the platform configuration file:**

```json
"ingestion_manager": {
  "interval": 30000
}
```

**Using environment variables:**

```bash
INGESTION_MANAGER__INTERVAL=30000
```

## TAXII feed settings

These settings apply to [TAXII Feeds](taxii-feed.md).

### Limit per request

Control the maximum number of objects retrieved per TAXII poll request using the `ingestion_manager:taxii_feed:limit_per_request` parameter.
Using 0 disables the limit.

**Default value**: 0 (unlimited)

**In the platform configuration file:**

```json
"ingestion_manager": {
  "taxii_feed": {
    "limit_per_request": 500
  }
}
```

**Using environment variables:**

```bash
INGESTION_MANAGER__TAXII_FEED__LIMIT_PER_REQUEST=500
```

## RSS feed settings

These settings apply to [RSS Feeds](rss-feed.md).

### Minimum interval

Set the minimum polling interval (in minutes) for RSS ingestion feeds using the `ingestion_manager:rss_feed:min_interval_minutes` parameter.
This prevents feeds from being polled too frequently.

### User agent

Customize the HTTP `User-Agent` header sent when fetching RSS feeds using the `ingestion_manager:rss_feed:user_agent` parameter if you have some issues of requests denied by the RSS feed server.

**Default values**:
- user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
- min_interval_minutes: 5

**In the platform configuration file:**

```json
"ingestion_manager": {
  "rss_feed": {
    "min_interval_minutes": 5,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
  }
}
```

**Using environment variables:**

```bash
INGESTION_MANAGER__RSS_FEED__MIN_INTERVAL_MINUTES=5
INGESTION_MANAGER__RSS_FEED__USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
```

## CSV feed settings

These settings apply to [CSV Feeds](csv-feed.md).

### Minimum interval

Set the minimum polling interval (in minutes) for CSV ingestion feeds using the `ingestion_manager:csv_feed:min_interval_minutes` parameter.

**Default value**: 5 (minutes)

**In the platform configuration file:**

```json
"ingestion_manager": {
  "csv_feed": {
    "min_interval_minutes": 5
  }
}
```

**Using environment variables:**

```bash
INGESTION_MANAGER__CSV_FEED__MIN_INTERVAL_MINUTES=5
```

## JSON feed settings

[JSON Feeds](json-feed.md) have no dedicated setting. The URI deny list and the ingestion manager interval above apply to them. A JSON feed with the **Platform default** schedule period runs at every ingestion manager check, with no minimum interval, unless data from its previous run is still waiting in its queue.
