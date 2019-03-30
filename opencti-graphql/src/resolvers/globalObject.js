const globalObjectResolvers = {
  GlobalObject: {
    __resolveType(obj) {
      if( obj.observable_value ) {
        return 'StixObservable';
      }
      if (obj.type) {
        return obj.type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    }
  }
};

export default globalObjectResolvers;
