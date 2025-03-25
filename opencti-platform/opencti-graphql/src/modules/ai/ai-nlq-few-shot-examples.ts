export const jsonFewShotExamples: {
  _comment: string;
  input: string;
  output: unknown;
}[] = [
  {
    _comment: 'I/ Identification of threat actors by TTP ID (T1082 technique)',
    input: "Who's is behind this T1082?",
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['T1082'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set',
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'I/ Identification of threat actors by report or incident',
    input: 'Who are the threats in the PolarEdge ORB report?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['PolarEdge ORB report'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Intrusion-Set',
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'II/ Targeting and Potential Victims by Relationship (targets)',
    input: 'Which risks are most likely to affect me?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: ['targets'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set',
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'II/ Targeting and Potential Victims by ID (e.g., Malicious IP)',
    input:
      'Which victims and industry sectors are being affected by 134.175.104.84?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: ['targets'],
            },
            {
              key: 'id',
              values: ['134.175.104.84'],
            },
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'III/ Relations and Behaviors - Tactics (uses)',
    input: 'How would Cyber Av3ngers carry out an attack on me?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['Cyber Av3ngers'],
            },
            {
              key: 'relationship_type',
              values: ['uses'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Attack-Pattern'],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'IV/ Malware and IOCs Linked to an Actor (uses)',
    input: 'Can you list the malware used by MustardMan?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['MustardMan'],
            },
            {
              key: 'relationship_type',
              values: ['uses'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Malware'],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'IV/ Malware and IOCs Linked to an Actor (without relationship)',
    input: 'Can you list the IOCs linked to APT-C-00 Ocean Lotus?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['APT-C-00  Ocean Lotus'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Indicator'],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'IV/ Malware and IOCs Linked to an Actor (related-to)',
    input:
      "Does the file named 'example_file' have any associations with known threat actors or cyber threats?",
    output: {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set',
          ],
          mode: 'or',
        },
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: ['related-to'],
            },
            {
              key: 'id',
              values: ['example_file'],
            },
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment:
      'V/ Intelligence Reports and Incidents - Creators or Assignees (creator_id)',
    input:
      'What intelligence reports have been released by the Cambridge Group of Clubs?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'creator_id',
          operator: 'eq',
          values: ['Cambridge Group of Clubs'],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Report'],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment:
      'V/ Intelligence Reports and Incidents - Creators or Assignees (objectAssignee)',
    input: 'Can you list all cybersecurity incidents assigned to John Doe?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Incident'],
          mode: 'or',
        },
        {
          key: 'objectAssignee',
          operator: 'eq',
          values: ['John Doe'],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment:
      'VI/ Diversification of Entities (here Vulnerabilities related to a TTP) (Attack-Pattern, Intrusion-Set, Malware, Indicator, Incident, Threat-Actor, Campaign (ny), Course-of-Action (ny), Tool (ny), Vulnerability, Report)',
    input: 'What vulnerabilities are associated with T1497?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [{ key: 'id', values: ['T1497'] }],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Vulnerability'],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment:
      'VII/ Diversity of Relationships (targets - Victims or industry sectors targeted by an IP) (uses, targets, related-to, located-at)',
    input: 'Which victims and industry sectors are targeted by 134.175.104.84?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            { key: 'relationship_type', values: ['targets'] },
            { key: 'id', values: ['134.175.104.84'] },
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment:
      'VII/ Diversity of Relationships (located-at - Geolocation of threat actors) (uses, targets, related-to, located-at, mitigates(ny), indicates(ny), compromises(ny))',
    input: 'Which actors are located in Russia?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            { key: 'relationship_type', values: ['located-at'] },
            { key: 'id', values: ['Russia'] },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set',
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: 'VIII/ General and Non-CTI Questions (returns empty filters)',
    input: 'What is the impact of quantum computing on encryption?',
    output: { mode: 'and', filters: [], filterGroups: [] },
  },
  {
    _comment:
      "VIII/ Grammatical and Linguistic Complexity (should return nothing as it's non-CTI)",
    input:
      'The sun, a radiant beacon in the sky, spread its golden warmth across the horizon, igniting the dawn with an explosion of brilliant color.',
    output: { mode: 'and', filters: [], filterGroups: [] },
  },
  {
    _comment:
      'IX/ Complex Questions and Linguistic Complexity: Passive Voice - Conditional Statements - TODO: Support conditional logic',
    input: 'If T1497 was involved, who would be responsible?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['T1497'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set',
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment:
      'IX/ Complex Questions and Linguistic Complexity: Indirect Questions - TODO: Interpret indirect questions',
    input: 'I wonder who is behind T1497.',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['T1497'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set',
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment:
      'IX/ Complex Questions and Linguistic Complexity: Logical Operators - TODO: Improve handling of logical operators (AND, OR)',
    input: 'Who uses either T1497 or T1082?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['T1497'],
            },
            {
              key: 'id',
              values: ['T1082'],
            },
            {
              key: 'relationship_type',
              values: ['uses'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set',
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: '',
    input: 'Show me vulnerabilities with a CVSS score > 3.5 and <= to 7.',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'x_opencti_cvss_base_score',
          values: ['3.5'],
          operator: 'gt', // strictly greater than 2
          mode: 'or',
        },
        {
          key: 'x_opencti_cvss_base_score',
          values: ['7'],
          operator: 'lte', // less than or equal to 7
          mode: 'or',
        },
        {
          key: 'entity_type',
          values: ['Vulnerability'],
          operator: 'eq',
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: '',
    input: "Retrieve all entities tagged with label 'apt50'.",
    output: {
      mode: 'and',
      filters: [
        {
          key: 'objectLabel',
          values: ['apt50'],
          operator: 'eq',
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: '',
    input: 'Find all geographical cities.',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          values: ['City'],
          operator: 'eq',
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: '',
    input: 'Who are the victims of APT28 in Europe?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: ['targets'],
            },
            {
              key: 'id',
              values: ['APT28'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: ['located-at'],
            },
            {
              key: 'id',
              values: ['Europe'],
            },
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
  {
    _comment: '',
    input: 'Find all incidents linked to APT28.',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: ['APT28'],
            },
          ],
          mode: 'or',
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Incident'],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  },
];
