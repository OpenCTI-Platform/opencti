const softwareResolvers = {
    Query: {
  
    },
    Mutation: {
  
    },
    // Map enum GraphQL values to data model required values
    FamilyType: {
      windows: 'windows',
      linux: 'linux',
      macos: 'macos',
      other: 'other',
    },
  };
  
  export default softwareResolvers;