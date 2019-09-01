// eslint-disable-next-line
export const resolveLink = (type) => {
  switch (type) {
    case 'attack-pattern':
      return '/dashboard/techniques/attack_patterns';
    case 'course-of-action':
      return '/dashboard/techniques/courses_of_action';
    case 'tool':
      return '/dashboard/techniques/tools';
    case 'vulnerability':
      return '/dashboard/techniques/vulnerabilities';
    case 'sector':
      return '/dashboard/entities/sectors';
    case 'region':
      return '/dashboard/entities/regions';
    case 'country':
      return '/dashboard/entities/countries';
    case 'city':
      return '/dashboard/entities/cities';
    case 'organization':
      return '/dashboard/entities/organizations';
    case 'user':
      return '/dashboard/entities/persons';
    case 'threat-actor':
      return '/dashboard/threats/threat_actors';
    case 'intrusion-set':
      return '/dashboard/threats/intrusion_sets';
    case 'campaign':
      return '/dashboard/threats/campaigns';
    case 'incident':
      return '/dashboard/threats/incidents';
    case 'malware':
      return '/dashboard/threats/malwares';
    case 'report':
      return '/dashboard/reports/all';
    case 'observable':
      return '/dashboard/observables/all';
    default:
      return null;
  }
};
