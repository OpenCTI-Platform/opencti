# Connectors

Connectors in OpenCTI serve as dynamic gateways, facilitating the import of data from a wide array of sources and systems. Every connector is designed to handle specific data types and structures of the source, allowing OpenCTI to efficiently ingest the data.

## Connector behaviors

The behavior of each connector is defined by its development, determining the types of data it imports and its configuration options. This flexibility allows users to customize the import process to their specific needs, ensuring a seamless and personalized data integration experience.

The level of configuration granularity regarding the imported data type varies with each connector. Nevertheless, connectors empower users to specify the date from which they wish to fetch data. This capability is particularly useful during the initial activation of a connector, enabling the retrieval of historical data. Following this, the connector operates in real-time, continuously importing new data from the source.

### Reset connector state

Resetting the connector state enables you to restart the ingestion process from the very beginning.
Additionally, resetting the connector state will purge the RabbitMQ queue for this specific connector.

However, this action requires the "Manage connector state" capability (more details about capabilities: [List of capabilities](../administration/users.md#list-of-capabilities)). Without this specific capability, you will not be able to reset the connector state.

When the action is performed, a message is displayed confirming the reset and inform you about the number of messages that will be purged

![Reset state message pop-up](../assets/reset-state-msg.png)

Purging a message queue is necessary to remove any accumulated messages that may be outdated or redundant. It helps to avoid reprocessing messages that have already been ingested.

By purging the queue, you ensure that the connector starts with a clean slate, processing only the new data.

### Connector Ecosystem

OpenCTI's connector ecosystem covers a broad spectrum of sources, enhancing the platform's capability to integrate data from various contexts, from threat intelligence providers to specialized databases. The list of available connectors can be found in our [connectors catalog](https://www.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76). Connectors are categorized into three types: import connectors (the focus here), [enrichment connectors](enrichment.md), and stream consumers. Further documentation on connectors is available on [the dedicated documentation page](../deployment/connectors.md).

In summary, automated imports through connectors empower OpenCTI users with a scalable, efficient, and customizable mechanism for data ingestion, ensuring that the platform remains enriched with the latest and most relevant intelligence.