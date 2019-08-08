import { importData } from '../domain/stixEntity';

const stixEntityResolvers = {
  StixEntity: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.observable_value) {
        return 'StixObservable';
      }
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    }
  },
  Mutation: {
    importData: (_, { type, file }) => importData(type, file)
  }
};

export default stixEntityResolvers;
