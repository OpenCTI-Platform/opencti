# Indicators Lifecycle Management


## Introduction

OpenCTI enforces strict rules to determine the period during which an indicator is effective for usage. This period is defined by the `valid_from` and `valid_until` dates. All along its lifecycle, the indicator `score` will decrease according to [configured decay rules](../administration/decay-rules.md). After the indicator expires, the object is marked as `revoked` and the `detection` field is automatically set to `false`. Here, we outline how these dates are calculated within the OpenCTI platform and how the score is updated with decay rules.


## Setting validity dates

### Data source provided the dates

If a data source provides `valid_from` and `valid_until` dates when creating an indicator on the platform, these dates are used without modification. But, if the creation is performed from the UI and the indicator is elligible to be manages by a decay rule, the platform will change this valid_until with the one calculated by the Decay rule.

### Fallback rules for unspecified dates

If a data source does not provide validity dates, OpenCTI applies the decay rule matching the indicator to determine these dates.
The `valid_until` date is computed based on the revoke score of the decay rule : it is set at the exact time at which the indicator will reach the revoke score.
Past `valid_until` date, the indicator is marked as revoked.

## Score decay

Indicators have an initial score at creation, either provided by data source, or 50 by default.
Over time, this score is going to decrease according to the configured decay rules.
Score is updated at each reaction point defined for the decay rule matching the indicator at creation.

## Example

This URL indicator has matched the `Built-in IP and URL` decay rule. Its initial score at creation is 100. 

![Indicator overview](./assets/indicators-lifecycle-example-overview.png)

Right next to the indicator score, there is a button `Lifecycle` which enables to open a dialog to see the details of the indicator's lifecyle.

![Indicator lifecycle](./assets/indicators-lifecycle-example-dialog.png)

## Conclusion

Understanding how OpenCTI calculates validity periods and scores is essential for effective threat intelligence analysis. These rules ensure that your indicators are accurate and up-to-date, providing a reliable foundation for threat intelligence data.
