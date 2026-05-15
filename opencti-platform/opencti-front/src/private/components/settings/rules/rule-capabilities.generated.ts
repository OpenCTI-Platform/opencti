/* eslint-disable */
// Generated from rule-slot-matrix-combined.csv. Do not edit manually.

export type RuleSlotKind = 'entity' | 'relationship';

export interface RuleSlotCapability {
  id: string;
  label: string;
  kind: RuleSlotKind;
  allowedEntityTypes: string[];
  multiType: boolean;
}

export interface RuleCapability {
  ruleId: string;
  ruleName: string;
  hasSightingEdge: boolean;
  ifRelations: string[];
  slots: RuleSlotCapability[];
}

export const RULE_CAPABILITIES: Record<string, RuleCapability> = {
  "attribution_attribution": {
    "ruleId": "attribution_attribution",
    "ruleName": "Attribution propagation",
    "hasSightingEdge": false,
    "ifRelations": [
      "attributed-to",
      "attributed-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Intrusion-Set",
          "Threat-Actor",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Individual",
          "Intrusion-Set",
          "Organization",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual"
        ],
        "multiType": true
      }
    ]
  },
  "attribution_indicator_indicates": {
    "ruleId": "attribution_indicator_indicates",
    "ruleName": "Indicator propagation via attribution",
    "hasSightingEdge": false,
    "ifRelations": [
      "attributed-to",
      "indicates"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Threat-Actor",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Individual",
          "Intrusion-Set",
          "Organization",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Indicator C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Indicator"
        ],
        "multiType": false
      }
    ]
  },
  "attribution_observable_related": {
    "ruleId": "attribution_observable_related",
    "ruleName": "Observable relation propagation via attribution",
    "hasSightingEdge": false,
    "ifRelations": [
      "attributed-to",
      "related-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Threat-Actor",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Individual",
          "Intrusion-Set",
          "Organization",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Observable C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      }
    ]
  },
  "attribution_targets": {
    "ruleId": "attribution_targets",
    "ruleName": "Targeting propagation via attribution",
    "hasSightingEdge": false,
    "ifRelations": [
      "targets",
      "attributed-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Threat-Actor",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Event",
          "Individual",
          "Organization",
          "Position",
          "Region",
          "Sector",
          "System",
          "Vulnerability"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Individual",
          "Intrusion-Set",
          "Organization",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual"
        ],
        "multiType": true
      }
    ]
  },
  "attribution_use": {
    "ruleId": "attribution_use",
    "ruleName": "Usage propagation via attribution",
    "hasSightingEdge": false,
    "ifRelations": [
      "uses",
      "attributed-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Threat-Actor",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Attack-Pattern",
          "Channel",
          "Infrastructure",
          "Malware",
          "Narrative",
          "StixFile",
          "Tool"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Individual",
          "Intrusion-Set",
          "Organization",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual"
        ],
        "multiType": true
      }
    ]
  },
  "belongs_to_attributed": {
    "ruleId": "belongs_to_attributed",
    "ruleName": "Belongs-to propagation via attribution",
    "hasSightingEdge": false,
    "ifRelations": [
      "belongs-to",
      "attributed-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Channel"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Intrusion-Set",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Individual",
          "Organization",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual"
        ],
        "multiType": true
      }
    ]
  },
  "indicate_sighted": {
    "ruleId": "indicate_sighted",
    "ruleName": "Inference of targeting via a sighting",
    "hasSightingEdge": true,
    "ifRelations": [
      "indicates",
      "stix-sighting-relationship"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Indicator A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Indicator"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Malware"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Individual",
          "Organization",
          "Position",
          "Region",
          "Sector",
          "System"
        ],
        "multiType": true
      }
    ]
  },
  "infrastructure_observable_related": {
    "ruleId": "infrastructure_observable_related",
    "ruleName": "Observable related to entity via infrastructure",
    "hasSightingEdge": false,
    "ifRelations": [
      "uses",
      "consists-of"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Infrastructure",
          "Intrusion-Set",
          "Malware",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Tool"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Infrastructure B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Infrastructure"
        ],
        "multiType": false
      },
      {
        "id": "C",
        "label": "Observable C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      }
    ]
  },
  "localization_of_targets": {
    "ruleId": "localization_of_targets",
    "ruleName": "Targeting propagation when located",
    "hasSightingEdge": false,
    "ifRelations": [
      "targets",
      "located-at"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "AI-Prompt",
          "Attack-Pattern",
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Malware",
          "StixFile",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Tool"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Event",
          "Individual",
          "Infrastructure",
          "Organization",
          "Position",
          "Region",
          "Sector",
          "Software",
          "System",
          "Vulnerability"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Targeting relation C",
        "kind": "relationship",
        "allowedEntityTypes": [
          "targets relationship"
        ],
        "multiType": false
      },
      {
        "id": "D",
        "label": "Location D",
        "kind": "entity",
        "allowedEntityTypes": [],
        "multiType": false
      }
    ]
  },
  "location_location": {
    "ruleId": "location_location",
    "ruleName": "Location propagation",
    "hasSightingEdge": false,
    "ifRelations": [
      "located-at",
      "located-at"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Location A",
        "kind": "entity",
        "allowedEntityTypes": [
          "City",
          "Country",
          "Position",
          "Region"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Location B",
        "kind": "entity",
        "allowedEntityTypes": [
          "City",
          "Country",
          "Position",
          "Region"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Location C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Region"
        ],
        "multiType": true
      }
    ]
  },
  "location_targets": {
    "ruleId": "location_targets",
    "ruleName": "Targeting propagation via location",
    "hasSightingEdge": false,
    "ifRelations": [
      "targets",
      "located-at"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Attack-Pattern",
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Malware",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Tool"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "City",
          "Country",
          "Individual",
          "Infrastructure",
          "Position",
          "Region",
          "Sector",
          "System"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Location C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Position",
          "Region"
        ],
        "multiType": true
      }
    ]
  },
  "observable_related": {
    "ruleId": "observable_related",
    "ruleName": "Relation propagation via an observable",
    "hasSightingEdge": false,
    "ifRelations": [
      "related-to",
      "related-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Observable A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Malware"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Malware"
        ],
        "multiType": true
      }
    ]
  },
  "observe_sighting": {
    "ruleId": "observe_sighting",
    "ruleName": "Sightings of observables via observed data",
    "hasSightingEdge": false,
    "ifRelations": [
      "created-by",
      "object",
      "based-on"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Observed Data A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Observed-Data"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Identity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Organization",
          "Sector",
          "System"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Observable C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      },
      {
        "id": "D",
        "label": "Indicator D",
        "kind": "entity",
        "allowedEntityTypes": [],
        "multiType": false
      }
    ]
  },
  "parent_technique_use": {
    "ruleId": "parent_technique_use",
    "ruleName": "Usage propagation of parent techniques",
    "hasSightingEdge": false,
    "ifRelations": [
      "uses",
      "subtechnique-of"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Campaign",
          "Hostname",
          "Incident",
          "Intrusion-Set",
          "Malware",
          "StixFile",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Tool"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Attack-Pattern"
        ],
        "multiType": false
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Attack-Pattern"
        ],
        "multiType": false
      }
    ]
  },
  "part_part": {
    "ruleId": "part_part",
    "ruleName": "Belonging propagation",
    "hasSightingEdge": false,
    "ifRelations": [
      "part-of",
      "part-of"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Intrusion-Set",
          "Sector",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Intrusion-Set",
          "Sector",
          "Threat-Actor-Group"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Intrusion-Set",
          "Organization",
          "Sector",
          "Threat-Actor-Group"
        ],
        "multiType": true
      }
    ]
  },
  "part-of_targets": {
    "ruleId": "part-of_targets",
    "ruleName": "Targeting propagation via belonging",
    "hasSightingEdge": false,
    "ifRelations": [
      "targets",
      "part-of"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Attack-Pattern",
          "Campaign",
          "Incident",
          "Intrusion-Set",
          "Malware",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Tool"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Identity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Sector"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Identity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Organization",
          "Sector"
        ],
        "multiType": true
      }
    ]
  },
  "participate-to_parts": {
    "ruleId": "participate-to_parts",
    "ruleName": "Organization propagation via participation",
    "hasSightingEdge": false,
    "ifRelations": [
      "participate-to",
      "part-of"
    ],
    "slots": [
      {
        "id": "A",
        "label": "User A",
        "kind": "entity",
        "allowedEntityTypes": [
          "User"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Organization B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Organization"
        ],
        "multiType": false
      },
      {
        "id": "C",
        "label": "Organization C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Organization"
        ],
        "multiType": false
      }
    ]
  },
  "related_related": {
    "ruleId": "related_related",
    "ruleName": "Relation propagation testing rule",
    "hasSightingEdge": false,
    "ifRelations": [
      "related-to",
      "related-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Entity A",
        "kind": "entity",
        "allowedEntityTypes": [
          "AI-Prompt",
          "Administrative-Area",
          "Artifact",
          "Attack-Pattern",
          "Autonomous-System",
          "Bank-Account",
          "Campaign",
          "Channel",
          "City",
          "Country",
          "Course-Of-Action",
          "Domain-Name",
          "Event",
          "Hostname",
          "ICCID",
          "IMEI",
          "IMSI",
          "IPv4-Addr",
          "IPv6-Addr",
          "Incident",
          "Indicator",
          "Individual",
          "Infrastructure",
          "Intrusion-Set",
          "Mac-Addr",
          "Malware",
          "Media-Content",
          "Narrative",
          "Observed-Data",
          "Organization",
          "Phone-Number",
          "Position",
          "Region",
          "Sector",
          "SecurityPlatform",
          "Software",
          "StixFile",
          "System",
          "Text",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual",
          "Tool",
          "Url",
          "User-Account",
          "Vulnerability"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "AI-Prompt",
          "Administrative-Area",
          "Artifact",
          "Attack-Pattern",
          "Autonomous-System",
          "Bank-Account",
          "Campaign",
          "Channel",
          "City",
          "Country",
          "Course-Of-Action",
          "Domain-Name",
          "Event",
          "Hostname",
          "ICCID",
          "IMEI",
          "IMSI",
          "IPv4-Addr",
          "IPv6-Addr",
          "Incident",
          "Indicator",
          "Individual",
          "Infrastructure",
          "Intrusion-Set",
          "Mac-Addr",
          "Malware",
          "Media-Content",
          "Narrative",
          "Observed-Data",
          "Organization",
          "Phone-Number",
          "Position",
          "Region",
          "Sector",
          "SecurityPlatform",
          "Software",
          "StixFile",
          "System",
          "Text",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual",
          "Tool",
          "Url",
          "User-Account",
          "Vulnerability"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "AI-Prompt",
          "Administrative-Area",
          "Artifact",
          "Attack-Pattern",
          "Autonomous-System",
          "Bank-Account",
          "Campaign",
          "Channel",
          "City",
          "Country",
          "Course-Of-Action",
          "Domain-Name",
          "Event",
          "Hostname",
          "ICCID",
          "IMEI",
          "IMSI",
          "IPv4-Addr",
          "IPv6-Addr",
          "Incident",
          "Indicator",
          "Individual",
          "Infrastructure",
          "Intrusion-Set",
          "Mac-Addr",
          "Malware",
          "Media-Content",
          "Narrative",
          "Observed-Data",
          "Organization",
          "Phone-Number",
          "Position",
          "Region",
          "Sector",
          "SecurityPlatform",
          "Software",
          "StixFile",
          "System",
          "Text",
          "Threat-Actor",
          "Threat-Actor-Group",
          "Threat-Actor-Individual",
          "Tool",
          "Url",
          "User-Account",
          "Vulnerability"
        ],
        "multiType": true
      }
    ]
  },
  "report_ref_identity_part_of": {
    "ruleId": "report_ref_identity_part_of",
    "ruleName": "Identities propagation in reports",
    "hasSightingEdge": false,
    "ifRelations": [
      "object",
      "part-of"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Report A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Report"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Identity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Organization",
          "Sector",
          "System"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Identity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Organization",
          "Sector",
          "System"
        ],
        "multiType": true
      }
    ]
  },
  "report_ref_indicator_based_on": {
    "ruleId": "report_ref_indicator_based_on",
    "ruleName": "Observables propagation in reports",
    "hasSightingEdge": false,
    "ifRelations": [
      "object",
      "based-on"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Report A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Report"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Indicator B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Indicator"
        ],
        "multiType": false
      },
      {
        "id": "C",
        "label": "Observable C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      }
    ]
  },
  "report_ref_location_located_at": {
    "ruleId": "report_ref_location_located_at",
    "ruleName": "Locations propagation in reports",
    "hasSightingEdge": false,
    "ifRelations": [
      "object",
      "located-at"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Report A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Report"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Location B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Position",
          "Region"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Location C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Position",
          "Region"
        ],
        "multiType": true
      }
    ]
  },
  "report_ref_observable_based_on": {
    "ruleId": "report_ref_observable_based_on",
    "ruleName": "Indicators propagation in reports",
    "hasSightingEdge": false,
    "ifRelations": [
      "object",
      "based-on"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Report A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Report"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Observable B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Indicator C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Indicator"
        ],
        "multiType": false
      }
    ]
  },
  "report_ref_observable_belongs_to": {
    "ruleId": "report_ref_observable_belongs_to",
    "ruleName": "Observables propagation in reports via belongs-to",
    "hasSightingEdge": false,
    "ifRelations": [
      "object",
      "belongs-to"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Report A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Report"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Observable B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Observable C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      }
    ]
  },
  "sighting_incident": {
    "ruleId": "sighting_incident",
    "ruleName": "Raise incident based on sighting",
    "hasSightingEdge": true,
    "ifRelations": [
      "has",
      "stix-sighting-relationship"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Indicator A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Indicator"
        ],
        "multiType": false
      },
      {
        "id": "C",
        "label": "Entity C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Individual",
          "Organization",
          "Sector",
          "System"
        ],
        "multiType": true
      }
    ]
  },
  "sighting_indicator": {
    "ruleId": "sighting_indicator",
    "ruleName": "Sightings propagation from indicator",
    "hasSightingEdge": true,
    "ifRelations": [
      "stix-sighting-relationship",
      "based-on"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Indicator A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Indicator"
        ],
        "multiType": false
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Individual",
          "Organization",
          "Position",
          "Region",
          "Sector",
          "System"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Observable C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      }
    ]
  },
  "sighting_observable": {
    "ruleId": "sighting_observable",
    "ruleName": "Sightings propagation from observable",
    "hasSightingEdge": true,
    "ifRelations": [
      "stix-sighting-relationship",
      "based-on"
    ],
    "slots": [
      {
        "id": "A",
        "label": "Observable A",
        "kind": "entity",
        "allowedEntityTypes": [
          "Artifact",
          "Autonomous-System",
          "Domain-Name",
          "Hostname",
          "IPv4-Addr",
          "IPv6-Addr",
          "Mac-Addr",
          "Software",
          "StixFile",
          "User-Account"
        ],
        "multiType": true
      },
      {
        "id": "B",
        "label": "Entity B",
        "kind": "entity",
        "allowedEntityTypes": [
          "Administrative-Area",
          "City",
          "Country",
          "Individual",
          "Organization",
          "Position",
          "Region",
          "Sector",
          "System"
        ],
        "multiType": true
      },
      {
        "id": "C",
        "label": "Indicator C",
        "kind": "entity",
        "allowedEntityTypes": [
          "Indicator"
        ],
        "multiType": false
      }
    ]
  }
};
