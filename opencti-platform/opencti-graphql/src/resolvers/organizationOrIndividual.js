const organizationOrIndividualResolvers = {
  OrganizationOrIndividual: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
      return 'Unknown';
    },
  },
};

export default organizationOrIndividualResolvers;
