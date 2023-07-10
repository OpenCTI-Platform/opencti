## Overview

!!! tip "Enterprise edition"

    Activity unified interface and logging are available under the "Filigran entreprise edition" license.

    [Please read the dedicated page to have all information](/administration/enterprise)


OpenCTI activity capability is the way to unified whats really happen in the platform.
With this feature you will be able to answer "who did what, where, and when?" within your data with the maximum level of transparency. 
Enabling activity helps your security, auditing, and compliance entities monitor platform for possible vulnerabilities or external data misuse.

## Categories

The activity group 3 different concepts that need to be explains.

### Basic knowledge

The basic knowledge refers to all stix data knowledge inside OpenCTI. Every create/update/delete actions on that knowledge is accessible through the history.
That basic activity is handled by the history manager and can be also found directly on each entity.

### Extended knowledge

The extended knowledge refers to extra information data to track specific user activity.
As this kind of tracking is expensive, the tracking will only be done for specific user/group/organization explicitly configured.

### Audit knowledge

Audit is focusing on user administration or security actions.
Audit will produces **console/logs** files along with user interface elements.

```json
{
  "auth": "<User information>",
  "category": "AUDIT",
  "level": "<info | error>",
  "message": "<human readable explanation>",
  "resource": {
    "type": "<authentication | mutation>",
    "event_scope": "<depends on type>",
    "event_access": "<administration>",
    "data": "<contextual data linked to the event type>",
    "version": "<version of audit log format>"
  },
  "timestamp": "<event date>",
  "version": "<platform version>"
}
```

## Architecture

OpenCTI use different mechanisms to be able to publish actions (audit) or data modification (history)

<iframe style="border: 1px solid rgba(0, 0, 0, 0.1);" width="800" height="450" src="https://www.figma.com/embed?embed_host=share&url=https://www.figma.com/file/65JHbbWWKftqLGrQJ0Xhml/Notifications-architecture?type=whiteboard&node-id=0%3A1&t=Q9GJ4psB6cAdQ3uR-1" allowfullscreen></iframe>

## Audit knowledge

!!! note "Administration or security actions"

    With Enterprise edition activated, Administration and security actions are always written; you can't configure, exclude, or disable them

    :white_check_mark: Supported
    
    :cross_mark: Not supported for now
    
    :prohibited: Not applicable

### Ingestion

| <div style="width:200px"></div>  | Create             | Delete              | Edit                |
|:---------------------------------|:-------------------|:--------------------|:--------------------|
| Remote OCTI Streams              | :white_check_mark: | :white_check_mark:  | :white_check_mark:  |

### Data sharing

| <div style="width:200px"></div>  | Create             | Delete              | Edit                |
|:---------------------------------|:-------------------|:--------------------|:--------------------|
| CSV Feeds                        | :white_check_mark: | :white_check_mark:  | :white_check_mark:  |
| TAXII Feeds                      | :white_check_mark: | :white_check_mark:  | :white_check_mark:  |
| Stream Feeds                     | :white_check_mark: | :white_check_mark:  | :white_check_mark:  |

### Connectors

| <div style="width:200px"></div> | Create              | Delete              | Edit                           |
|:--------------------------------|:--------------------|:--------------------|:-------------------------------|
| Connectors                      | :white_check_mark:  | :white_check_mark:  | :white_check_mark: State reset |
| Works                           | :prohibited:        | :white_check_mark:  | :prohibited:                   |

### Parameters

| <div style="width:200px"></div> | Create        | Delete        | Edit                |
|:--------------------------------|:--------------|:--------------|:--------------------|
| Platform parameters             | :prohibited:  | :prohibited:  | :white_check_mark:  |

### Security

| <div style="width:200px"></div> | Create             | Delete             | Edit                   |
|:--------------------------------|:-------------------|:-------------------|:-----------------------|
| Roles                           | :white_check_mark: | :white_check_mark: | :white_check_mark:     |
| Groups                          | :white_check_mark: | :white_check_mark: | :white_check_mark:     |
| Users                           | :white_check_mark: | :white_check_mark: | :white_check_mark:     |
| Sessions                        | :prohibited:       | :white_check_mark: | :prohibited:           |
| Policies                        | :prohibited:       | :prohibited:       | :white_check_mark:     |

### Customization

| <div style="width:200px"></div> | Create             | Delete             | Edit                |
|:--------------------------------|:-------------------|:-------------------|:--------------------|
| Entity types                    | :prohibited:       | :prohibited:       | :white_check_mark:  |
| Rules engine                    | :prohibited:       | :prohibited:       | :white_check_mark:  |
| Retention policies              | :white_check_mark: | :white_check_mark: | :white_check_mark:  |

### Taxonomies

| <div style="width:200px"></div> | Create              | Delete              | Edit                |
|:--------------------------------|:--------------------|:--------------------|:--------------------|
| Status templates                | :white_check_mark:  | :white_check_mark:  | :white_check_mark:  |
| Case templates + tasks          | :white_check_mark:  | :white_check_mark:  | :white_check_mark:  |

### Accesses

| <div style="width:200px"></div> | Listen             |     |     |
|:--------------------------------|:-------------------|-----|-----|
| Login (success or fail)         | :white_check_mark: |     |     |
| Logout                          | :white_check_mark: |     |     |
| Unauthorized access             | :white_check_mark: |     |     |

## Extended knowledge

!!! note "Extended knowledge"

    Extented knowledge activity are written only if you activate the feature for a subset of users / groups or organizations

### Data management

Some history actions are already included in the "basic knowledge". (basic marker) 

| <div style="width:200px"></div> | Read                | Create              | Delete              | Edit                |
|:--------------------------------|---------------------|:--------------------|:--------------------|:--------------------|
| Platform knowledge              | :white_check_mark:  | basic               | basic               | basic               |
| Background tasks Knowledge      | :prohibited:        | :white_check_mark:  | :white_check_mark:  | :prohibited:        |
| Knowledge files                 | :white_check_mark:  | basic               | basic               | :prohibited:        |
| Global data import files        | :white_check_mark:  | :white_check_mark:  | :white_check_mark:  | :prohibited:        |
| Analyst workbenches files       | :prohibited:        | :white_check_mark:  | :white_check_mark:  | :prohibited:        |
| Triggers                        | :prohibited:        | :white_check_mark:  | :white_check_mark:  | :cross_mark:        |
| Workspaces                      | :white_check_mark:  | :white_check_mark:  | :white_check_mark:  | :cross_mark:        |
| Investigations                  | :white_check_mark:  | :white_check_mark:  | :white_check_mark:  | :cross_mark:        |
| User profile                    | :prohibited:        | :prohibited:        | :prohibited:        | :white_check_mark:  |

### User actions

| <div style="width:200px"></div> | Supported           |     |     |     |
|:--------------------------------|:--------------------|-----|-----|-----|
| Ask for file import             | :white_check_mark:  |     |     |     |
| Ask for data enrichment         | :white_check_mark:  |     |     |     |
| Ask for export generation       | :white_check_mark:  |     |     |     |
| Execute global search           | :white_check_mark:  |     |     |     |