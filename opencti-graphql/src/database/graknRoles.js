const rolesMap = {
  uses: {
    'threat-actor': ['malware', 'tool', 'attack-pattern'],
    'intrusion-set': ['malware', 'tool', 'attack-pattern'],
    campaign: ['malware', 'tool', 'attack-pattern'],
    incident: ['malware', 'tool', 'attack-pattern'],
    malware: ['tool', 'attack-pattern'],
    tool: ['attack-pattern']
  },
  targets: {
    'threat-actor': [
      'sector',
      'region',
      'country',
      'city',
      'organization',
      'user',
      'vulnerability'
    ],
    'intrusion-set': [
      'sector',
      'region',
      'country',
      'city',
      'organization',
      'user',
      'vulnerability'
    ],
    campaign: [
      'sector',
      'region',
      'country',
      'city',
      'organization',
      'user',
      'vulnerability'
    ],
    incident: [
      'sector',
      'region',
      'country',
      'city',
      'organization',
      'user',
      'vulnerability'
    ],
    malware: [
      'sector',
      'region',
      'country',
      'city',
      'organization',
      'user',
      'vulnerability'
    ]
  },
  'attributed-to': {
    'intrusion-set': ['threat-actor'],
    campaign: ['threat-actor', 'intrusion-set'],
    incident: ['threat-actor', 'intrusion-set', 'campaign']
  },
  mitigates: {
    'course-of-action': ['attack-pattern']
  },
  localization: {
    country: ['region'],
    city: ['region', 'country'],
    organization: ['region', 'country', 'city']
  },
  gathering: {
    sector: ['sector'],
    organization: ['sector'],
    user: ['organization']
  }
};

export const isInversed = (relationType, fromType, toType) => {
  if (fromType && toType) {
    if (rolesMap[relationType]) {
      if (
        rolesMap[relationType][fromType] &&
        rolesMap[relationType][fromType].includes(toType)
      ) {
        return false;
      }
      if (
        rolesMap[relationType][toType] &&
        rolesMap[relationType][toType].includes(fromType)
      ) {
        return true;
      }
    }
  }
  return false;
};
