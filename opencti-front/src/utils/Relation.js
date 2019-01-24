const relationsTypesMapping = {
  'campaign_intrusion-set': ['attributed-to'],
  'campaign_attack-pattern': ['uses'],
  campaign_county: ['targets'],
  campaign_city: ['targets'],
  campaign_sector: ['targets'],
  campaign_organization: ['targets', 'attributed-to'],
  'campaign_threat-actor': ['attributed-to'],
  campaign_user: ['attributed-to', 'targets'],
  campaign_malware: ['uses'],
  campaign_vulnerability: ['targets'],
  'intrusion-set_attack-pattern': ['uses'],
  'intrusion-set_country': ['targets', 'localization'],
  'intrusion-set_city': ['targets', 'localization'],
  'intrusion-set_sector': ['targets'],
  'intrusion-set_organization': ['targets', 'attributed-to'],
  'intrusion-set_threat-actor': ['targets', 'attributed-to'],
  'intrusion-set_user': ['attributed-to'],
  'intrusion-set_malware': ['uses'],
  'intrusion-set_vulnerability': ['targets'],
};

export const resolveRelationsTypes = (fromType, toType) => relationsTypesMapping[`${fromType}_${toType}`];

export const resolveRoles = (type) => {
  switch (type) {
    case 'targets':
      return { fromRole: 'source', toRole: 'target' };
    case 'uses':
      return { fromRole: 'user', toRole: 'usage' };
    case 'attributed-to':
      return { fromRole: 'attribution', toRole: 'origin' };
    case 'variant-of':
      return { fromRole: 'variation', toRole: 'original' };
    case 'gathering':
      return { fromRole: 'part_of', toRole: 'gather' };
    case 'related-to':
      return { fromRole: 'relate_from', toRole: 'relate_to' };
    case 'localization':
      return { fromRole: 'localized', toRole: 'location' };
    default:
      return { fromRole: '', toRole: '' };
  }
};

export default resolveRoles;
