import { DiamondEntityEnum, DiamondNodeEnum } from './types/nodes/diamondEnums';

const filterContentFromEntityTypeAndNodeType = {
  [DiamondEntityEnum.threatActorGroup]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Campaign', 'Intrusion-Set', 'Incident'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityEnum.threatActorIndividual]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Campaign', 'Intrusion-Set', 'Incident'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityEnum.intrusionSet]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Intrusion-Set', 'Campaign', 'Threat-Actor-Group', 'Threat-Actor-Individual'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityEnum.campaign]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Incident'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'hosts', 'owns', 'related-to'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityEnum.malware]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual'],
      relationships: ['authored-by'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'exfiltrates-to', 'beacons-to', 'communicates-to'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Tool'],
      relationships: ['uses', 'downloads', 'drops'],
    },
  },
  [DiamondEntityEnum.channel]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Incident'],
      relationships: ['uses'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'related-to'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware'],
      relationships: ['uses', 'delivers', 'drops'],
    },
  },
  [DiamondEntityEnum.tool]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Incident'],
      relationships: ['uses'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['uses', 'related-to'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware'],
      relationships: ['uses', 'delivers', 'drops'],
    },
  },
  [DiamondEntityEnum.incident]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign'],
      relationships: ['attributed-to'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['related-to', 'uses'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Attack-Pattern', 'Malware', 'Tool', 'Channel'],
      relationships: ['uses'],
    },
  },
  [DiamondEntityEnum.infrastructure]: {
    [DiamondNodeEnum.adversary]: {
      entityType: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign', 'Incident'],
      relationships: ['uses', 'hosts', 'owns'],
    },
    [DiamondNodeEnum.infrastructure]: {
      entityType: ['IPv4-Addr', 'IPv6-Addr', 'Infrastructure', 'Domain-Name'],
      relationships: ['with', 'consists'],
    },
    [DiamondNodeEnum.capabilities]: {
      entityType: ['Malware', 'Tool'],
      relationships: ['controls', 'hosts', 'delivers'],
    },
  },
};

export const getFilterFromEntityTypeAndNodeType = (entity_type: DiamondEntityEnum, nodeType: DiamondNodeEnum) => {
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
