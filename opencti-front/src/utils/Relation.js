const relationsTypesMapping = {
  'threat-actor_attack-pattern': ['uses'],
  'threat-actor_region': ['targets'],
  'threat-actor_country': ['targets', 'attributed-to'],
  'threat-actor_city': ['targets'],
  'threat-actor_sector': ['targets'],
  'threat-actor_organization': ['targets'],
  'threat-actor_user': ['targets', 'attributed-to'],
  'threat-actor_malware': ['uses'],
  'threat-actor_tool': ['uses'],
  'threat-actor_vulnerability': ['targets'],
  'intrusion-set_attack-pattern': ['uses'],
  'intrusion-set_region': ['targets', 'localization'],
  'intrusion-set_country': ['targets', 'localization', 'attributed-to'],
  'intrusion-set_city': ['targets', 'localization', 'attributed-to'],
  'intrusion-set_sector': ['targets'],
  'intrusion-set_organization': ['targets', 'attributed-to'],
  'intrusion-set_threat-actor': ['targets', 'attributed-to'],
  'intrusion-set_user': ['targets', 'attributed-to'],
  'intrusion-set_tool': ['uses'],
  'intrusion-set_malware': ['uses'],
  'intrusion-set_vulnerability': ['targets'],
  'campaign_threat-actor': ['attributed-to'],
  'campaign_intrusion-set': ['attributed-to'],
  'campaign_attack-pattern': ['uses'],
  campaign_region: ['targets'],
  campaign_country: ['targets'],
  campaign_city: ['targets'],
  campaign_sector: ['targets'],
  campaign_organization: ['targets', 'attributed-to'],
  campaign_user: ['attributed-to', 'targets'],
  campaign_malware: ['uses'],
  campaign_tool: ['uses'],
  campaign_vulnerability: ['targets'],
  incident_region: ['targets'],
  incident_country: ['targets'],
  incident_city: ['targets'],
  incident_organization: ['targets', 'attributed-to'],
  incident_sector: ['targets'],
  'incident_threat-actor': ['attributed-to'],
  'incident_intrusion-set': ['attributed-to'],
  incident_campaign: ['attributed-to'],
  incident_malware: ['uses'],
  incident_vulnerability: ['targets'],
  'malware_attack-pattern': ['uses'],
  malware_region: ['targets'],
  malware_country: ['targets', 'attributed-to'],
  malware_city: ['targets', 'attributed-to'],
  malware_organization: ['targets', 'attributed-to'],
  malware_sector: ['targets'],
  malware_user: ['targets', 'attributed-to'],
  malware_vulnerability: ['targets'],
  malware_tool: ['uses'],
  malware_malware: ['variant-of'],
  country_region: ['localization'],
  city_country: ['localization'],
  organization_country: ['localization'],
  organization_city: ['localization'],
  organization_sector: ['gathering'],
  user_organization: ['gathering'],
  user_country: ['localization'],
  user_city: ['localization'],
  'attack-pattern_attack-pattern': ['comes-after'],
};

export const resolveRelationsTypes = (fromType, toType) => (relationsTypesMapping[`${fromType}_${toType}`] ? relationsTypesMapping[`${fromType}_${toType}`] : []);

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
    case 'comes-after':
      return { fromRole: 'coming_from', toRole: 'coming_after' };
    default:
      return { fromRole: '', toRole: '' };
  }
};
