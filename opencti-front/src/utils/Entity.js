export const resolveLink = (type) => {
  switch (type) {
    case 'attack-pattern':
      return '/dashboard/catalogs/attack_patterns';
    case 'region':
      return '/dashboard/catalogs/regions';
    case 'country':
      return '/dashboard/catalogs/countries';
    case 'city':
      return '/dashboard/catalogs/cities';
    case 'organization':
      return '/dashboard/catalogs/organizations';
    case 'user':
      return '/dashboard/catalogs/persons';
    case 'threat-actor':
      return '/dashboard/knowledge/threat_actors';
    case 'sector':
      return '/dashboard/knowledge/sectors';
    case 'intrusion-set':
      return '/dashboard/knowledge/intrusion_sets';
    case 'campaign':
      return '/dashboard/knowledge/campaigns';
    case 'incident':
      return '/dashboard/knowledge/incidents';
    case 'malware':
      return '/dashboard/knowledge/malwares';
    case 'tool':
      return '/dashboard/catalogs/tools';
    case 'vulnerability':
      return '/dashboard/catalogs/vulnerabilities';
    case 'report':
      return '/dashboard/reports/all';
    case 'observable':
      return '/dashboard/observables/all';
    default:
      return null;
  }
};