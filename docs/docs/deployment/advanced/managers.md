# Platform managers

Platform managers are background components that perform various tasks to support some important functionalities in the platform.

Here is a list of all the managers on the platform:

## Rules engine

Allows users to execute pre-defined actions based on the data and events in the platform.

These rules are accessible in Settings > Customization > Rules engine.

The rules engine is designed to help users automate and streamline their cyber threat intelligence processes.

More information can be found [here](../../administration/reasoning.md).

## History manager

This manager keeps tracks of user/connector interactions on entities in the platform.

It is designed to help users audit and understand the evolution of their CTI data.

## Knowledge snapshot manager

This manager supports the [knowledge time machine](../../usage/time-machine.md). Once a week, it takes a compact snapshot of every entity changed since the previous snapshot, including the entities whose only change is a relationship created, updated or deleted: its attribute values and the identifiers of its relationships by type, as they were at the snapshot date. Rebuilding an entity at a past date then starts from the closest snapshot instead of replaying the whole history.

The manager also deletes, at every hourly run, the snapshots older than the shortest active History retention rule. The "new since your last visit" markers are not handled here: the [retention manager](#retention-manager) expires them after one year and removes them when their user is deleted, so it must stay enabled for that cleanup to run.

## Activity manager

The activity manager in OpenCTI is a component that monitors and logs the user actions in the platform such as login, settings update, and user activities if configured (read, update, etc.).

More information can be found [here](../../administration/audit/overview.md).

## Background task manager

Is a component that handles the execution of tasks, such as importing data, exporting data and mass operations.

More information can be found [here](../../usage/background-tasks.md).

## Expiration scheduler

The expiration scheduler is responsible for monitoring expired elements in the platform.
It cancels the access rights of expired user accounts and revokes expired indicators from the platform.

## Synchronization manager

The synchronization manager enables the data sharing between multiple OpenCTI platforms. 
It allows the user to create and configure synchronizers which are processes that connect to the live streams of remote OpenCTI platforms and import the data into the local platform. 

## Retention manager

The retention manager is a component that allows the user to define rules to help delete data in OpenCTI that is no longer relevant or useful. This helps to optimize the performance and storage of the OpenCTI platform and ensures the quality and accuracy of the data.

It also expires the "new since your last visit" markers of the [knowledge time machine](../../usage/time-machine.md) after one year (`time_machine:visit_retention_days`) and removes the markers of deleted users. The knowledge snapshots themselves are deleted by the [knowledge snapshot manager](#knowledge-snapshot-manager).

More information can be found [here](../../administration/retentions.md).

## Notification manager

The notification manager is a component that allows the user to customize and receive alerts about events/changes in the platform.

The [change digests](../../usage/time-machine.md#change-digests) of its digest schedule compute the landscape changes of each recipient apart from the schedule itself, two at a time, so a long computation never delays another digest. Each due digest is recorded in Redis until every notifier of its recipient received it: a busy platform or a restart delays it instead of dropping it, and the platform that takes over the notification manager sends it. Redis also keeps the end of the last period recorded per change digest: a delivery time that passed while no notification manager was running is recorded at the next pass, and its digest covers every change since the previous one (at most one week before its usual period). Each digest is computed under its own lock, so a handover of the notification manager between platforms never sends it twice. The publisher manager keeps a receipt per digest and notifier: 15 minutes after a digest is stored, a notifier without a receipt (the platform stopped while it was sending, or the notifier failed) gets the digest again, and only that notifier. While a notifier sends, its receipt is held by the sending platform and renewed; if the receipt cannot be kept, the sending is cancelled before another platform may take it over (a webhook call is cancelled; an email already handed to the mail server is still delivered and recorded, and a possible double delivery is reported in the logs). A digest that cannot be built or stored is tried again 5, 10, 20 and 40 minutes later; a digest makes five attempts at most, failed or stored, and one that still did not reach every notifier is reported in the logs; a digest still waiting a week after the end of its period is not sent any more.

More information can be found [here](../../usage/notifications.md).

## Ingestion manager

The ingestion manager in OpenCTI is a component that manages the ingestion of data from RSS, TAXII and CSV feeds.

More information can be found [here](../../usage/getting-started.md).

## Playbook manager

The playbook manager handles the automation scenarios which can be fully customized and enabled by platform administrators to enrich, filter and modify the data created or updated in the platform.

Please read the [Playbook automation page](../../usage/playbook-automation.md) to get more information.

## File index manager

The file indexing manager extracts and indexes the text content of the files, and stores it in the database.
It allows users to search for text content within files uploaded to the platform.

More information can be found [here](../../administration/file-indexing.md).

## Indicator decay manager

The indicator decay manager allows to update indicators score automatically based on configured decay rules.

More information can be found:
- [Decay rule configuration](../../administration/decay-rules.md).
- [Indicator lifecycle](../../usage/indicators-lifecycle.md).

## Trash manager

The trash manager is responsible to delete permanently elements stored in the [trash](../../usage/delete-restore.md) after a specified period of time (7 days by default).

## Data sanity manager

The data sanity manager runs periodic or on demand operations to improve data consistency.
There is no UI yet, but some GraphQL operations can be found in the dedicated page: [Data sanity manager](../../usage/dataSanityManager.md).

## Filigran telemetry manager

The telemetry manager collects periodically statistical data about platform usage.

More information about data telemetry can be found [here](../../reference/usage-telemetry.md).
