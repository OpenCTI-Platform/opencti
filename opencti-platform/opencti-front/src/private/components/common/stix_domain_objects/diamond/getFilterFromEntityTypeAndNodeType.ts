export enum DiamondNodeType {
  adversary = 'adversary',
  infrastructure = 'infrastructure',
  capabilities = 'capabilities',
}

export enum DiamondEntityType {
  threatActorGroup = 'Threat-Actor-Group',
  threatActorIndividual = 'Threat-Actor-Individual',
  intrusionSet = 'Intrusion-Set',
  campaign = 'Campaign',
  malware = 'Malware',
  channel = 'Channel',
  tool = 'Tool',
  incident = 'Incident',
}

const filterContentFromEntityTypeAndNodeType = {
  [DiamondEntityType.threatActorGroup]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Campaign', 'Intrusion-Set', 'Incident'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityType.threatActorIndividual]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Campaign', 'Intrusion-Set', 'Incident'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityType.intrusionSet]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Campaign', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Intrusion-Set'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityType.campaign]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Incident'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityType.malware]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual'],
      relationships: ['authored-by'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'exfiltrates-to', 'beacons-to', 'communicates-to'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Tool'],
      relationships: ['uses', 'downloads', 'drops'],
    },
  },
  [DiamondEntityType.channel]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual'],
      relationships: ['uses'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'related-to'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware'],
      relationships: ['uses', 'delivers', 'drops'],
    },
  },
  [DiamondEntityType.tool]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Incident'],
      relationships: ['uses'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'related-to'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware'],
      relationships: ['uses', 'delivers', 'drops'],
    },
  },
  [DiamondEntityType.incident]: {
    [DiamondNodeType.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeType.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['related-to', 'uses'],
    },
    [DiamondNodeType.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
};

const getFilterFromEntityTypeAndNodeType = (entity_type: DiamondEntityType, nodeType: DiamondNodeType) => {
  const filterContent = filterContentFromEntityTypeAndNodeType[entity_type][nodeType];

  const filterGroups = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        operator: 'eq',
        values: [...filterContent.entityType],
        mode: 'or',
      },
      {
        key: 'regardingOf',
        operator: 'eq',
        values: [
          {
            key: 'relationship_type',
            values: [...filterContent.relationships],
          },
        ],
        mode: 'or',
      },
    ],
    filterGroups: [],
  };

  return encodeURIComponent(JSON.stringify(filterGroups));
};

export default getFilterFromEntityTypeAndNodeType;
