# Rate limiting

OpenCTI includes a built-in HTTP rate limiter that protects the platform against abusive or excessive request patterns. The rate limiter is applied globally to all incoming HTTP requests, including GraphQL queries, before session handling occurs.

## How it works

The rate limiter uses a sliding time window to track the number of requests per unique client. Each client is identified by a combination of its **IP address** and **User-Agent** header, meaning two different user agents behind the same IP are tracked independently.

When a client exceeds the configured maximum number of requests within the time window, subsequent requests receive a `429 Too Many Requests` response until the window resets.

## Configuration parameters

All rate limiting parameters are configured under `app:rate_protection` in the platform configuration file, or via environment variables.

| Parameter                                      | Environment variable                             | Default | Description                                                                                                                                                   |
|:-----------------------------------------------|:-------------------------------------------------|:--------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `app:rate_protection:max_requests`             | `APP__RATE_PROTECTION__MAX_REQUESTS`             | `10000` | Maximum number of requests allowed per client (IP + User-Agent) within the time window. Set to `0` to deny all requests.                                      |
| `app:rate_protection:time_window`              | `APP__RATE_PROTECTION__TIME_WINDOW`              | `1`     | Duration of the sliding time window in **seconds**. Values below 1 are treated as 1 second.                                                                   |
| `app:rate_protection:ip_skip_list`             | `APP__RATE_PROTECTION__IP_SKIP_LIST`             | `[]`    | JSON array of exact IP addresses that bypass rate limiting entirely.                                                                                          |
| `app:rate_protection:ip_skip_ranges`           | `APP__RATE_PROTECTION__IP_SKIP_RANGES`           | `[]`    | JSON array of CIDR ranges whose matching IPs bypass rate limiting. Supports both IPv4 and IPv6.                                                               |
| `app:rate_protection:user_agent_skip_prefixes` | `APP__RATE_PROTECTION__USER_AGENT_SKIP_PREFIXES` | `[]`    | JSON array of User-Agent prefixes. Requests whose `User-Agent` header starts with any of these values are not rate limited. Matching is **case-insensitive**. |

## Skipping rate limits

You can exempt specific clients from rate limiting in three ways. A request is skipped if **any** of the following conditions is met:

### By exact IP address

Add specific IP addresses to the `ip_skip_list` array:

```json
{
  "app": {
    "rate_protection": {
      "ip_skip_list": ["127.0.0.1", "::1", "10.0.0.42"]
    }
  }
}
```

Or via environment variable:

```bash
APP__RATE_PROTECTION__IP_SKIP_LIST='["127.0.0.1", "::1", "10.0.0.42"]'
```

### By IP range (CIDR notation)

Add CIDR ranges to the `ip_skip_ranges` array. This is useful for whitelisting entire subnets, such as internal networks or trusted reverse proxies:

```json
{
  "app": {
    "rate_protection": {
      "ip_skip_ranges": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    }
  }
}
```

Or via environment variable:

```bash
APP__RATE_PROTECTION__IP_SKIP_RANGES='["192.168.0.0/16", "10.0.0.0/8"]'
```

Both IPv4 and IPv6 CIDR notation are supported (e.g., `fd00::/8`). You can also specify single IP addresses inside this array — they will be treated as exact matches.

### By User-Agent prefix

Add User-Agent prefixes to the `user_agent_skip_prefixes` array. This is useful for exempting browser traffic or specific bots:

```json
{
  "app": {
    "rate_protection": {
      "user_agent_skip_prefixes": ["Mozilla", "MyTrustedBot"]
    }
  }
}
```

Or via environment variable:

```bash
APP__RATE_PROTECTION__USER_AGENT_SKIP_PREFIXES='["Mozilla", "MyTrustedBot"]'
```

The matching is **case-insensitive**: a prefix of `"Mozilla"` matches user agents like `Mozilla/5.0 (Windows NT 10.0; ...)` and `mozilla/5.0`.

## Example: full configuration

Below is a complete example combining all rate limiting options:

```json
{
  "app": {
    "rate_protection": {
      "max_requests": 5000,
      "time_window": 10,
      "ip_skip_list": ["127.0.0.1"],
      "ip_skip_ranges": ["10.0.0.0/8", "192.168.0.0/16"],
      "user_agent_skip_prefixes": ["Mozilla"]
    }
  }
}
```

This configuration:

- Allows up to **5000 requests per 10 seconds** per client.
- Skips rate limiting for the loopback address `127.0.0.1`.
- Skips rate limiting for any IP in the `10.0.0.0/8` or `192.168.0.0/16` ranges (typical private networks).
- Skips rate limiting for requests from browsers (whose User-Agent typically starts with `Mozilla`).

