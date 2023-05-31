# Nested references and objects

## STIX standard

### Definition

In the [STIX 2.1 standard](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html), objects can:

1. Refer to other objects in directly in their `attributes`, by referencing one or multiple IDs.
2. Have other objects directly embedded in the entity.

### Example

```json
{
   "type": "intrusion-set",
   "spec_version": "2.1",
   "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
   "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff", // nested reference to an identity
   "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"], // nested reference to multiple marking defintions
   "external_references": [
      {
         "source_name": "veris",
         "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
         "url": "https://github.com/vz-risk/VCDB/blob/125307638178efddd3ecfe2c267ea434667a4eea/data/json/validated/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",    
      }
   ],
   "created": "2016-04-06T20:03:48.000Z",
   "modified": "2016-04-06T20:03:48.000Z",
   "name": "Bobcat Breakin",
   "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access...",
   "aliases": ["Zookeeper"],
   "goals": ["acquisition-theft", "harassment", "damage"]
}
```

In the previous example, we have 2 nested references to other objects in:

```json
"created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff", // nested reference to an identity
"object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"], // nested reference to multiple marking defintions
```

But we also have a nested object within the entity (an `External Reference`):

```json
"external_references": [
   {
      "source_name": "veris",
      "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
      "url": "https://github.com/vz-risk/VCDB/blob/125307638178efddd3ecfe2c267ea434667a4eea/data/json/validated/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",    
   }
]
```

## Implementation

### Modelization

In OpenCTI, all nested references and objects are modelized as relationships, to be able to pivot more easily on labels, external references, kill chain phases, marking definitions, etc.

![Investigation](assets/investigation.png)

### Import & export

When importing and exporting data to/from OpenCTI, the translation between nested references and objects to full-fledged nodes and edges is automated and therefore transparent for the users.

```json

```