## STIX 2.1 Relationship Parser

The stix_documentation_parser script downloads and parses the https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html documentation and aims at automatically extracting all relationships (including nested relationships). To speed up multiple parsing attempts, the documentation is also saved as `stix-v2.1-os.html`.

The `opencti_custom.json` file contains all custom STIX relationships which are implemented in OpenCTI.

The result of the parser script will be a JSON file for the frontend (`stix_relationships-frontend.json`) and the backend (`stix_relationships-backend.json`) tests.
The only difference is that the backend JSON file uses a template strings for all SCOs "<all_SCOs>" while for the frontend every single relationship to an SCO will be mentioned.

Execution:
```shell
$ python3 stix_documentation_parser.py 
```

## Custom OpenCTI Relationships

Relationship to assign a `location` to an `ipX-address`.
```json
"ipv4-addr": {
  "location": [
    "located-at"
  ]
},
"ipv6-addr": {
  "location": [
    "located-at"
  ]
}
```

MITRE subtechnique-of relationships for `attack-pattern`
```json
"attack-pattern": {
  "attack-pattern": [
    "subtechnique-of"
  ]
}
```

Inter-`identity` relationships
```json
"individual": {
  "individual": [
    "part-of"
  ],
  "organization": [
    "part-of"
  ]
},
"organization": {
  "organization": [
    "part-of"
  ],
  "sector": [
    "part-of"
  ]
},
"sector": {
  "sector": [
    "part-of"
  ]
}
```
Custom `system` relationships
```json
"system": {
  "organization": [
    "belongs-to"
  ],
  "region": [
    "located-at"
  ]
}
```
Custom `incident` relationship (since for STIX 2.1 `incident` is only a stub)  
```json
"incident": {
  "campaign": [
    "attributed-to"
  ]
}
```
Custom `indicator` relationships
```json
"indicator": {
  "indicator": [
    "derived-from"
  ],
  "vulnerability": [
    "indicates"
  ],
  "<all_SCOs>": [
    "based-on"
  ]
}
```
Inter `location` relationships
```json
"city": {
  "country": [
    "located-at"
  ],
  "region": [
    "located-at"
  ]
},
"country": {
  "region": [
    "located-at"
  ]
},
"position": {
  "city": [
    "located-at"
  ]
},
"region": {
  "region": [ 
    "located-at"
  ]
}           
```

Custom inter `threat-actor` relationship
```json
"threat-actor": {
  "threat-actor": [
    "part-of"
  ]
}
```

Custom targets relationship with `system` identity
```json
"campaign": {
    "system": [
      "targets"
    ]
  },
  "malware": {
    "system": [
      "targets"
    ]
  },
  "intrusion-set": {
    "system": [
      "targets"
    ]
  }
```