# Feeds advanced configuration

Some configuration can be done with environment variables or in the platform configuration file to fine tune feeds ingestion.
This page lists the available configuration parameters.

## URI deny list

Platform administrators can restrict which URIs are allowed for ingestion feeds (CSV, RSS, TAXII, and JSON) by configuring a deny list. When a user attempts to create or update an ingestion feed with a URI that matches a denied pattern, the platform rejects the request with an error.

This is useful for preventing ingestion from internal services, known-bad sources, or any other hosts that should not be accessed by the platform.

### Configuration

The deny list is configured via the `ingestion_manager:uri_deny_list` parameter. It accepts a JSON array of URI patterns.

**Default value**: [] (no deny list)

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

* Exact match: Deny any URI with a specific host (e.g. `mydomain.com`).
* Wildcard: Deny any URI with a host that matches a wildcard pattern (e.g. `*.mydomain.com`).
* Host with port: Deny any URI with a specific host and port combination (e.g `localhost:4200`).

!!! note "Pattern matching details"

    - Matching is **case-insensitive**.
    - The deny list applies to all ingestion feed types: CSV, RSS, TAXII, and JSON.
    - The check is performed at feed creation, feed update (when the URI changes), and at fetch time.
    - Wildcard patterns (`*.domain.com`) match both subdomains and the base domain itself.

## TAXII feed settings

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
