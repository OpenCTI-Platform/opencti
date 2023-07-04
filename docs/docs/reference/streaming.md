# Data Streaming

## Presentation

In order to provide a real time way to consume STIX CTI information, OpenCTI provides data events in a stream that can be consume to react on creation, update, deletion and merge.
This way of getting information out of OpenCTI is highly efficient and already use by some connectors.

## Technology

### Redis stream

OpenCTI is currently using REDIS Stream (See [https://redis.io/topics/streams-intro](https://redis.io/topics/streams-intro)) as the technical layer.
Each time something is modified in the OpenCTI database, a specific event is added in the stream.

### SSE protocol

In order to provides a really easy consuming protocol we decide to provide a SSE ([https://fr.wikipedia.org/wiki/Server-sent_events](https://fr.wikipedia.org/wiki/Server-sent_events)) http URL linked to the standard login system of OpenCTI.
Any user with the correct access rights can open and access http://opencti_instance/stream and open an SSE connection to start receiving live events. You can of course consume directly the stream in Redis but you will have to manage access and rights directly.

## Events format

```
id: {Event stream id} -> Like 1620249512318-0
event: {Event type} -> create / update / delete
data: { -> The complete event data
    version -> The version number of the event
    type -> The inner type of the event
    scope -> The scope of the event [internal or external]
    data: {STIX data} -> The STIX representation of the data.
    message -> A simple string to easy understand the event
    origin: {Data Origin} -> Complex object with different information about the origin of the event
    context: {Event context} -> Complex object with meta information depending of the event type
}
```

Id can be used to consume the stream from this specific point.

## STIX data

The current stix data representation is based on the STIX 2.1 format using extension mechanism.
Please take a look to [https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) for more information.

### Create

Its simply the data created in STIX format.

### Delete

Its simply the data in STIX format **just before his deletion**.
You will also find the automated deletions in context due to automatic dependency management.

```json
{
  "context": {
      "deletions": [{STIX data}]
  }
}
```

### Update

This event type publish the complete STIX data information along with patches information.
Thanks to the patches, its possible to rebuild the previous version and easily understand that happens in the update.
patch and reverse_patch follow the official jsonpatch specification. You can find more information at [https://jsonpatch.com/](https://jsonpatch.com/)

```json
{
  "context": {
      "patch": [/* patch operation object */],
      "reverse_patch": [/* patch operation object */]
  }
}
```

### Merge

Merge is a mix of an update of the merge targets and deletions of the sources.
In this event you will find the same patch and reverse_patch as an update and the list of elements merged into the target in the "sources" attribute.

```json
{
  "context": {
      "patch": [/* patch operation object */],
      "reverse_patch": [/* patch operation object */],
      "sources": [{STIX data}]
  }
}
```

## Stream types

In OpenCTI we propose 2 types of streams.

### Base stream

The stream hosted in /stream url contains all the raw events of the platform, **always** filtered by the user rights (marking based).
It's a technical stream a bit complex to used but very useful for internal processing or some specific connectors like backup/restore.
This stream is live by default but if you want to catchup you can simply add the from parameter to your query.
This parameter accept a timestamp in millisecond and also an event id.
Like http://localhost/stream?from=1620249512599

!!! tip "Stream size?"

    The raw stream is really important in the platform and needs te be sized according to the period of retention you want to ensure.
    More retention you will have, more security about reprocessing the past information you will get.
    We usually recommand 1 month of retention, that usually match 2 000 000 of events.
    This limit can be configured with redis:trimming option, please check [deployment configuration page](../deployment/configuration.md#redis).


### Live stream

This stream aims to simplify your usage of the stream through the connectors, providing a way to create stream with specific filters through the UI.
After creating this stream, is simply accessible from /stream/{STREAM_ID}.

It's very useful for various cases of data externalization, synchronization, like SPLUNK, TANIUM...

This stream provides different interesting mechanics:

- Stream the initial list of instances matching your filters when connecting based on main database if you use the recover parameter
- Auto dependencies resolution to guarantee the consistency of the information distributed
- Automatic events translation depending on the element segregation

**If you want to dig in about the internal behavior you can check this complete diagram:**

<iframe style="border: 1px solid rgba(0, 0, 0, 0.1);" width="800" height="450" src="https://www.figma.com/embed?embed_host=share&url=https://www.figma.com/file/Nar8HH9mfPP77NMA2LdyVi/OpenCTI---Stream-%26-Sync?type=whiteboard&node-id=0%3A1&t=YVQnLKlLAg1TdgBT-1" allowfullscreen></iframe>

#### General options

- **no-dependencies** (query parameter or header, default false). Can be used to prevent the auto dependencies resolution. To be used with caution.
- **listen-delete** (query parameter or header, default true). Can be used prevent receive deletion events. To be used with caution.
- **with-inferences** (query parameter or header, default false). Can be used to add inferences events (from rule engine) in the stream.

#### From and Recover

From and recover are 2 different options that need to be explains.

- **from** (query parameter) is always the parameter that describe the initial date/event_id you want to start from.
Can also be setup with request header **from** or **last-event-id** 

- **recover** (query parameter) is an option that let you consume the initial event from the database and not from the stream. 
Can also be setup with request header **recover** or **recover-date** 

This difference will be transparent for the consumer but very important to get old information as an initial snapshot.
This also let you consume information that is no longer in the stream retention period.

**The next diagram will help you to understand the concept:**

<iframe style="border: 1px solid rgba(0, 0, 0, 0.1);" width="800" height="250" src="https://www.figma.com/embed?embed_host=share&url=https://www.figma.com/file/khKEdn2uBcYqvp96EfwTgU/OpenCTI---Stream-live-options?type=whiteboard&node-id=0%3A1&t=5DyeKM6ppvlaIDIE-1" allowfullscreen></iframe>