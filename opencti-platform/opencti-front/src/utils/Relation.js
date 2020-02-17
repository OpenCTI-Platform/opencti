import { append } from 'ramda';

const relationsTypesMapping = {
  'attack-pattern_vulnerability': ['targets'],
  'threat-actor_attack-pattern': ['uses'],
  'threat-actor_region': ['targets', 'localization'],
  'threat-actor_country': ['targets', 'localization'],
  'threat-actor_city': ['targets', 'localization'],
  'threat-actor_sector': ['targets'],
  'threat-actor_organization': ['targets'],
  'threat-actor_user': ['targets'],
  'threat-actor_malware': ['uses'],
  'threat-actor_tool': ['uses'],
  'threat-actor_vulnerability': ['targets'],
  'intrusion-set_attack-pattern': ['uses'],
  'intrusion-set_region': ['targets'],
  'intrusion-set_country': ['targets'],
  'intrusion-set_city': ['targets'],
  'intrusion-set_sector': ['targets'],
  'intrusion-set_organization': ['targets', 'attributed-to'],
  'intrusion-set_threat-actor': ['attributed-to', 'targets'],
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
  campaign_user: ['targets', 'attributed-to'],
  campaign_malware: ['uses'],
  campaign_tool: ['uses'],
  campaign_vulnerability: ['targets'],
  'incident_attack-pattern': ['uses'],
  incident_region: ['targets'],
  incident_country: ['targets'],
  incident_city: ['targets'],
  incident_organization: ['targets', 'attributed-to'],
  incident_user: ['targets', 'attributed-to'],
  incident_sector: ['targets'],
  'incident_threat-actor': ['attributed-to'],
  'incident_intrusion-set': ['attributed-to'],
  incident_campaign: ['attributed-to'],
  incident_malware: ['uses'],
  incident_vulnerability: ['targets'],
  'malware_attack-pattern': ['uses'],
  malware_region: ['targets'],
  malware_country: ['targets'],
  malware_city: ['targets'],
  malware_organization: ['targets', 'attributed-to'],
  malware_sector: ['targets'],
  malware_user: ['targets', 'attributed-to'],
  'malware_threat-actor': ['attributed-to'],
  malware_vulnerability: ['targets'],
  malware_tool: ['uses', 'drops'],
  malware_malware: ['variant-of', 'drops'],
  country_region: ['localization'],
  city_country: ['localization'],
  city_region: ['localization'],
  sector_sector: ['gathering'],
  organization_country: ['localization'],
  organization_city: ['localization'],
  organization_region: ['localization'],
  organization_sector: ['gathering'],
  'organization_threat-actor': ['gathering'],
  organization_organization: ['gathering'],
  user_organization: ['gathering'],
  user_country: ['localization'],
  user_city: ['localization'],
  targets_country: ['localization'],
  targets_city: ['localization'],
  targets_region: ['localization'],
  'indicator_stix-relation': ['indicates'],
  indicator_stix_relation: ['indicates'],
  indicator_uses: ['indicates'],
  'indicator_threat-actor': ['indicates'],
  'indicator_intrusion-set': ['indicates'],
  indicator_campaign: ['indicates'],
  indicator_malware: ['indicates'],
  indicator_tool: ['indicates'],
  indicator_vulnerability: ['indicates'],
  observable_organization: ['gathering'],
  observable_person: ['gathering'],
  observable_city: ['localization'],
  observable_country: ['localization'],
  observable_region: ['localization'],
  'ipv4-addr_domain': ['resolves'],
  'ipv6-addr_domain': ['resolves'],
  'ipv4-addr_autonomous-system': ['belongs'],
  'ipv6-addr_autonomous-system': ['belongs'],
  domain_domain: ['resolves'],
  'file-name_file-path': ['corresponds'],
  'file-name_file-md5': ['corresponds'],
  'file-name_file-sha1': ['corresponds'],
  'file-name_file-sha256': ['corresponds'],
  'file-path_file-name': ['corresponds'],
  'file-path_file-md5': ['corresponds'],
  'file-path_file-sha1': ['corresponds'],
  'file-path_file-sha256': ['corresponds'],
  'file-md5_file-name': ['corresponds'],
  'file-md5_file-path': ['corresponds'],
  'file-md5_file-sha1': ['corresponds'],
  'file-md5_file-sha256': ['corresponds'],
  'file-sha1_file-name': ['corresponds'],
  'file-sha1_file-path': ['corresponds'],
  'file-sha1_file-md5': ['corresponds'],
  'file-sha1_file-sha256': ['corresponds'],
  'file-sha256_file-name': ['corresponds'],
  'file-sha256_file-path': ['corresponds'],
  'file-sha256_file-md5': ['corresponds'],
  'file-sha256_file-sha1': ['corresponds'],
};

export const resolveRelationsTypes = (fromType, toType, relatedTo = true) => {
  if (relatedTo) {
    return relationsTypesMapping[`${fromType}_${toType}`]
      ? append('related-to', relationsTypesMapping[`${fromType}_${toType}`])
      : ['related-to'];
  }
  return relationsTypesMapping[`${fromType}_${toType}`]
    ? relationsTypesMapping[`${fromType}_${toType}`]
    : [];
};

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
    case 'drops':
      return { fromRole: 'dropping', toRole: 'dropped' };
    case 'indicates':
      return { fromRole: 'indicator', toRole: 'characterize' };
    case 'linked':
      return { fromRole: 'link_from', toRole: 'link_to' };
    case 'resolves':
      return { fromRole: 'resolving', toRole: 'resolved' };
    case 'belongs':
      return { fromRole: 'belonging_to', toRole: 'belonged_to' };
    case 'corresponds':
      return { fromRole: 'correspond_from', toRole: 'correspond_to' };
    default:
      return { fromRole: '', toRole: '' };
  }
};
