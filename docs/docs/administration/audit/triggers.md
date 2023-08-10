# Activity triggers

!!! tip "Enterprise edition"

    Activity unified interface and logging are available under the "Filigran entreprise edition" license.

    [Please read the dedicated page to have all information](../enterprise.md)

## Description

Having all the history in the user interface ([events](events.md)) its sometimes not enough to have a proactive monitoring.
For this reason you can configure some specific triggers to receive notifications on audit events.
You can configure like personal triggers, lives one that will be sent directly or digest depending on your needs. 

## Configuration

In this kind of trigger you will have to configure different options:
- Notification target: User interface or email
- Recipients: who will receive the notification
- Filters: a set of filters to get only events that really interested you. (who is responsible for this event, kind of events, ...)

## Event structure

In order to correctly configure the filters, here's a definition of the event structure

- Event type: `authentication`
  - Event scopes: `login` and `logout` 

- Event type: `read`
    - Event scopes: `read` and `unauthorized` 

- Event type: `file`
    - Event scopes: `read`, `create` and `delete`

- Event type: `mutation`
    - Event scopes: `unauthorized`, `update `, `create` and `delete`

- Event type: `command`
    - Event scopes: `search `, `enrich `, `import` and `export`