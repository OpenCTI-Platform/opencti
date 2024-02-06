# Platform managers

Platform managers are background components that perform various tasks to support some important functionalities in the platform.

Here is a list of all the managers on the platform:

## Rules engine

Allows users to execute pre-defined actions based on the data and events in the platform.

These rules are accessible in Settings > Customization > Rules engine.

The rules engine is designed to help users automate and streamline their cyber threat intelligence processes.

More information can be found [here](../administration/reasoning.md).

## History manager

This manager keeps tracks of user/connector interactions on entities in the platform.

It is designed to help users audit and understand the evolution of their CTI data.

## Activity manager

The activity manager in OpenCTI is a component that monitors and logs the user actions in the platform such as login, settings update, and user activities if configured (read, udpate, etc.).

More information can be found [here](../administration/audit/overview.md).

## Background task manager

Is a component that handles the execution of tasks, such as importing data, exporting data and mass operations.

More information can be found [here](../usage/background-tasks.md).

## Expiration scheduler

The expiration scheduler is responsible for monitoring expired elements in the platform.
It cancels the access rights of expired user accounts and revokes expired indicators from the platform.

## Synchronization manager

The synchronization manager enables the data sharing between multiple OpenCTI platforms. 
It allows the user to create and configure synchronizers which are processes that connect to the live streams of remote OpenCTI platforms and import the data into the local platform. 

## Retention manager

The retention manager is a component that allows the user to define rules to help delete data in OpenCTI that is no longer relevant or useful. This helps to optimize the performance and storage of the OpenCTI platform and ensures the quality and accuracy of the data.

More information can be found [here](../administration/retentions.md).

## Notification manager

The notification manager is a component that allows the user to customize and receive alerts about events/changes in the platform.

More information can be found [here](../usage/notifications.md).

## Ingestion manager

The ingestion manager in OpenCTI is a component that manages the ingestion of data from RSS and TAXII feeds.

## Playbook manager

The playbook manager handles the automation scenarios which can be fully customized and enabled by platform administrators to enrich, filter and modify the data created or updated in the platform.

Please read the [Playbook automation page](../usage/automation.md) to get more information.

## File index manager

The file indexing manager extracts and indexes the text content of the files, and stores it in the database.
It allows users to search for text content within files uploaded to the platform.

More information can be found [here](../administration/file-indexing.md).
