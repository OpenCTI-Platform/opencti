# Overview

OpenCTI notifiers allow you to define templates for notifications triggered by events in the platform. These templates are written using **EJS (Embedded JavaScript templates)**, which enables you to manipulate the data included in the notifications dynamically.

When a notifier is triggered, it receives several data structures that can be used within your EJS templates to customize the notification content.

# Available variables

Each notifier template has access to four main variables:

| **Variable** | **Description** |
| --- | --- |
| `data` | Contains the raw data of the notification, including the instance (i.e. the object), type, and detailed STIX fields. |
| `content` | A simplified summary of the notification events, including `title`, `events`, `operation`, and `message`. |
| `notification` | Metadata about the notification and trigger itself, including ID, type, filters used, and associated notifiers. |
| `user` | Information about the user who triggered or is associated with the notifier, including email and notifier IDs. |

## Examples of outputs

### Data

```
<%-JSON.stringify(data)%>
```

- **Output example of a live trigger on a modification of a Report:**
    
    ```
    [
        {
            "notification_id": "5a7b1649-3310-480d-8396-9114fe68a647",
            "instance": {
                "id": "report--74192245-2790-59f5-84a0-d04ce249bb84",
                "spec_version": "2.1",
                "type": "report",
                "extensions": {
                    "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                        "extension_type": "property-extension",
                        "id": "6335912b-0747-4e5c-8e27-6b4c30056254",
                        "type": "Report",
                        "created_at": "2025-07-18T09:14:22.495Z",
                        "updated_at": "2025-08-26T23:09:32.154Z",
                        "stix_ids": [
                            "report--b9d12c1f-a20b-5115-af6a-b7270a140560"
                        ],
                        "is_inferred": false,
                        "creator_ids": [
                            "5736e1d6-2ae3-42fb-bd41-4815421557d8"
                        ],
                        "assignee_ids": [
                            "88ec0c6a-13ce-5e39-b486-354fe4a7084f"
                        ],
                        "participant_ids": [
                            "af39f8f3-b4ca-4835-bd7c-10f581a32b03"
                        ],
                        "workflow_id": "b28a370a-317b-4c50-8f0d-483b17d11abb",
                        "labels_ids": [
                            "d9f0f068-565b-4a7f-8049-00471c2e61ff"
                        ],
                        "created_by_ref_id": "06914efb-35f7-4387-a191-64c4bfa35c52",
                        "content": " This is the content of my Report ",
                        "reliability": "A - Completely reliable"
                    }
                },
                "created": "2025-07-18T09:01:17.436Z",
                "modified": "2025-08-26T23:09:32.154Z",
                "revoked": false,
                "confidence": 50,
                "lang": "en",
                "labels": [
                    "test",
                    "ransomware",
                    "menu issues"
                ],
                "object_marking_refs": [
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                ],
                "created_by_ref": "identity--e52b2fa3-2af0-5e53-ad38-17d54b3d61cb",
                "external_references": [
                    {
                        "source_name": "AlienVault",
                        "url": "https://www.morphisec.com/blog/ransomware-threat-matanbuchus-3-0-maas-levels-up"
                    },
                    {
                        "source_name": "AlienVault",
                        "url": "https://otx.alienvault.com/pulse/687a0d5dc93942c183eddbf5",
                        "external_id": "687a0d5dc93942c183eddbf5"
                    }
                ],
                "name": "This is my Report title",
                "description": "This is my Report description",
                "report_types": [
                    "threat-report"
                ],
                "published": "2025-07-18T09:01:17.436Z",
                "object_refs": [
                    "malware--d763a010-75cb-592e-821b-e66f16a68b3b"
                ]
            },
            "type": "update",
            "message": "[report] This is my Report title - John Doe adds menu issues in Label"
        }
    ]
    ```
    

### Content

```
<%-JSON.stringify(content)%>
```

- **Output example of a live trigger on a modification of a Report:**
    
    ```
    [
        {
            "title": "This is my Report title",
            "events": [
                {
                    "operation": "update",
                    "message": "[report] This is my Report title - John Doe adds menu issues in Label",
                    "instance_id": "report--74192245-2790-59f5-84a0-d04ce249bb84",
                    "entity_internal_id": "5d1c3f6e-3c1b-4a8e-9f3d-5b1f0a2c7d10",
                    "entity_type": "Report"
                }
            ]
        }
    ]
    ```

    `instance_id` is the id of the instance (the STIX standard id for knowledge events). The standard id changes when an attribute it is computed from changes (a rename for example), so build links to the platform on `entity_internal_id`, which never changes: `/dashboard/id/<%= event.entity_internal_id || event.instance_id %>` (the fallback covers notifications created before `entity_internal_id` existed).
    

### Notification

```
<%-JSON.stringify(notification)%>
```

- **Output example of a live trigger on a modification of a Report:**
    
    ```json
    {
        "_index": "opencti_internal_objects-000002",
        "_id": "5a7b1649-3310-480d-8396-9114fe68a647",
        "id": "5a7b1649-3310-480d-8396-9114fe68a647",
        "sort": [
            "trigger--13e9de8b-e656-53d9-9693-20c3897045c3"
        ],
        "standard_id": "trigger--13e9de8b-e656-53d9-9693-20c3897045c3",
        "restricted_members": [
            {
                "id": "7d136d4f-339a-4883-8d0d-a25a87a281a7",
                "access_right": "admin"
            }
        ],
        "internal_id": "5a7b1649-3310-480d-8396-9114fe68a647",
        "parent_types": [
            "Basic-Object",
            "Internal-Object"
        ],
        "i_attributes": [
            {
                "name": "notifiers",
                "updated_at": "2025-08-26T17:54:30.042Z",
                "user_id": "7d136d4f-339a-4883-8d0d-a25a87a281a7",
                "confidence": 100
            }
        ],
        "created": "2025-08-26T14:02:51.893Z",
        "trigger_type": "live",
        "confidence": 100,
        "authorized_authorities": [
            "SETTINGS_SETACCESSES",
            "VIRTUAL_ORGANIZATION_ADMIN"
        ],
        "description": "",
        "created_at": "2025-08-26T14:02:51.893Z",
        "filters": "{\"mode\":\"and\",\"filters\":[{\"key\":[\"entity_type\"],\"operator\":\"eq\",\"values\":[\"Report\"],\"mode\":\"or\"},{\"key\":[\"objectLabel\"],\"operator\":\"eq\",\"values\":[\"d9f0f068-565b-4a7f-8049-00471c2e61ff\"],\"mode\":\"or\"}],\"filterGroups\":[]}",
        "entity_type": "Trigger",
        "base_type": "ENTITY",
        "event_types": [
            "update"
        ],
        "instance_trigger": false,
        "updated_at": "2025-08-26T14:02:51.893Z",
        "trigger_scope": "knowledge",
        "notifiers": [
            "dafc0096-0c4c-4161-99c6-e57a238f53a7",
            "f4ee7b33-006a-4b0d-b57d-411ad288653d"
        ],
        "recipients": [],
        "name": "Test",
        "creator_id": [
            "7d136d4f-339a-4883-8d0d-a25a87a281a7"
        ],
        "updated": "2025-08-26T14:02:51.893Z"
    }
    ```
    

### User

```
<%-JSON.stringify(user)%>
```

- **Output example of a live trigger on a modification of a Report:**
    
    ```
    {
        "user_id": "7d136d4f-339a-4883-8d0d-a25a87a281a7",
        "user_email": "john.doe@filigran.io",
        "notifiers": [
            "dafc0096-0c4c-4161-99c6-e57a238f53a7",
            "f4ee7b33-006a-4b0d-b57d-411ad288653d"
        ]
    }
    ```
    

# Live triggers vs digests

OpenCTI supports two notification modes:

- **Live trigger:** Sends a notification immediately for each matching event.
- **Digest:** Accumulates multiple matching events over a defined period and delivers them in a single notification.

More details are available in the OpenCTI documentation: https://docs.opencti.io/latest/usage/notifications/

### Impact on notifier variables

Both `data` and `content` are returned as lists.

- With a **live trigger**, these lists contain **only one element** (the single event that triggered the notification).
- With a **digest**, these lists may contain **multiple elements**, each corresponding to one of the grouped notifications.

### Example: Handling multiple events in a digest

```
<% content.forEach(function(item) { %>
  Report Title: <%= item.title %>
  <% item.events.forEach(function(event) { %>
    - Operation: <%= event.operation %>
    - Message: <%= event.message %>
  <% }) %>
<% }) %>
```

# Using EJS

You can use EJS syntax to dynamically render values from the available variables:

- `<%= variable %>`: Outputs the variable as plain text.
- `<%- variable %>`: Outputs the variable as unescaped HTML/JSON.
- `<% %>`: Executes JavaScript code without rendering output.

### Example Template

```
Notification for <%=user.user_email%>:<br><br>

Report Title: <%=content[0].title%><br>
Message: <%=content[0].events[0].message%><br>

Labels:
<% data[0].instance.labels.forEach(function(label){ %>
  <br>- <%=label%>
<% }) %>
```

- **Output example of a trigger on a modification of a Report:**
    
    ```json
    Notification for john.doe@filigran.io:
    
    Report Title: This is my Report title
    Message: [report] This is my Report title - `John Doe` adds `trojanized files` in `Label`
    Labels: 
    - menu issues 
    - test 
    - ransomware 
    - trojanized files 
    ```
    

# Title variables

The **Title** of the Platform mailer is the subject of the email. In addition to EJS, you can insert notification data in it with `$` variables, without writing any `<% %>` tag.

A variable is a `$` followed by a path into the notification data:

- The first segment is a **root**. The available roots are `notification`, `notification_content`, `content`, `data`, `settings`, `user`, `platform_uri`, `doc_uri` and `url_suffix`. They hold the same data as in the message template.
- It is followed by any number of `.property` or `[index]` (a non-negative integer, starting at 0).
- `.length` gives the number of elements of a list, for instance `$data.length`.

| **Variable** | **Value** |
| --- | --- |
| `$notification.name` | Name of the trigger |
| `$notification.trigger_type` | `live` or `digest` |
| `$notification_content[0].title` | Name of the first entity concerned |
| `$notification_content[0].events[0].operation` | `create`, `update`, `delete`... |
| `$notification_content[0].events[0].message` | Message of the event |
| `$data[0].instance.name`, `$data[0].instance.type` | Name and type of the STIX object of the first event |
| `$data.length` | Number of events in the email |
| `$settings.platform_title` | Title of the platform |
| `$user.user_email` | Email of the recipient |

### Examples

- **Live trigger**, title `[$notification.name] $notification_content[0].events[0].operation - $notification_content[0].title`:

    ```
    [My trigger] update - APT-X
    ```

- **Digest**, title `[$notification.name] $data.length events, first: $notification_content[0].title`:

    ```
    [My digest] 5 events, first: APT-X
    ```

In a digest, pick the event you want with an explicit index: there is no implicit "first event".

### Rules

- A variable whose root is **not** in the list above is left as is, so `$100` or `$foo` stay literal text in the title.
- A variable with a known root but nothing at that path (an index out of range, a missing property, an empty value) is replaced by an **empty text**.
- A `.` that is not followed by a property name is not part of the variable: in `$notification.name.` the final dot stays in the title.
- A property name reads as many letters, digits and `_` as it finds: `$notification.name_x` reads the property `name_x`, which does not exist, so it is replaced by an empty text. Put a space or a punctuation mark right after a variable when text follows it.
- A list of plain values (for instance the labels) is rendered with its elements joined by `, `. An object is rendered as an empty text: go down to one of its properties instead.
- A title that already contains a bare word such as `$user`, `$data` or `$content` now renders it as an empty text, because these are known roots. Rewrite the title if you meant the literal word.
- Variables inside EJS tags (`<% %>`) are never rewritten. Use the regular EJS variables there.
- `notification_content` groups the events **by entity**, whereas `data` lists the events one by one. In a digest, `$notification_content[1]` and `$data[1]` can therefore concern different events. Use the same root for all the pieces of information that must go together.
- Only `$user.user_email` is available on `user`. The name of the recipient is not provided to the templates.
- The title is plain text and is **not HTML-escaped**: a value such as `R&D` appears as is in the subject, including with `<%= %>`. The title is also normalized: line breaks are replaced by spaces, repeated spaces are collapsed and the title is trimmed.

You can check a title with the **Test** button of the notifier: it sends a test email using a trigger named `[TEST] ...` and example entities, so every variable above has a value.

# Best practices

1. Use `content` for readable summaries and `data` for full STIX object details.
2. Avoid heavy computation in templates.
3. Escape output if sending to HTML/Email to avoid injection issues.

# External resources

To go further, please explore the following resources:

- **EJS documentation:** https://ejs.co/
- **OpenCTI custom notifiers documentation:** https://docs.opencti.io/latest/administration/notifiers/
- **OpenCTI notifiers template:** https://docs.opencti.io/latest/administration/notifier-samples/
- **Webhooks in OpenCTI blogpost:** https://filigran.io/webhooks-in-opencti-now-supported-in-triggers-and-digests/


 

