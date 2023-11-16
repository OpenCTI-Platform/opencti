# Indicators Lifecycle Management

## Introduction

OpenCTI enforces strict rules to determine the period during which an indicator is effective for detection. This period is defined by the `valid_from` and `valid_until` dates. In the future, all along this life, the indicator `score` will decrease according to a customizable algorithm.

After the indicator fully expires, the object is marked as `revoked` and the `detection` field is automatically set to `false`. Here, we outline how these dates are calculated within the OpenCTI platform. This documentation will be enhanced also for the score impact.


## Setting validity dates

### Data source provided the dates

If a data source provides `valid_from` and `valid_until` dates when creating an indicator on the platform, these dates are used without modification.

### Fallback rules for unspecified dates

If a data source does not provide validity dates, OpenCTI applies specific rules to determine these dates based on the "main observable type" of indicator and its associated markings.

| Indicator type                        | Marking                          | TTL (in days)  |
|:--------------------------------------|:---------------------------------|:--------------:|
| IPv4-Addr and IPv6-Addr               | `TLP:CLEAR` to `TLP:AMBER`       |       30       |
| IPv4-Addr and IPv6-Addr               | `TLP:AMBER+STRICT` and `TLP:RED` |       60       |
| IPv4-Addr and IPv6-Addr               | Others                           |       60       |
| URL                                   | `TLP:CLEAR` to `TLP:GREEN`       |       60       |
| URL                                   | `TLP:AMBER` to `TLP:RED`         |      180       |
| URL                                   | Others                           |      180       |
| Others (e.g. Domain-Name, File, YARA) | All                              |      365       |

### Understanding time-to-Live (TTL)

The TTL represents the duration for which an indicator is considered valid - i.e. here, the number of days between `valid_from` and `valid_until`. After this period, the indicator is marked as revoked.

### Example

If a URL indicator with `TLP:AMBER` marking is created without specific validity dates, it will be considered valid for 180 days from its `valid_from` date. After 180 days, the `valid_until` date will be reach and the indicator will be automatically revoked.


## Conclusion

Understanding how OpenCTI calculates validity periods is essential for effective threat intelligence analysis. These rules ensure that your indicators are accurate and up-to-date, providing a reliable foundation for threat intelligence data.