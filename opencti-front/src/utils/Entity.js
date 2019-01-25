export const resolveLink = (type) => {
  switch (type) {
    case 'country':
    case 'city':
    case 'organization':
      return null;
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
      return '/dashboard/knowledge/tools';
    case 'vulnerability':
      return '/dashboard/knowledge/vulnerabilities';
    default:
      return null;
  }
};
