const stixDomainResolvers = {
  StixDomain: {
    __resolveType(obj) {
      switch (obj.type) {
        case 'intrusion-set':
          return 'IntrusionSet';
        case 'malware':
          return 'Malware';
        case 'report':
          return 'Report';
        default:
          return 'Unkown';
      }
    }
  }
};

export default stixDomainResolvers;
