import {
  importData,
  findById,
  markingDefinitions,
  stixRelations
} from '../domain/stixEntity';

const stixEntityResolvers = {
  Query: {
    stixEntity: (_, { id }) => findById(id)
  },
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
    },
    markingDefinitions: (stixEntity, args) =>
      markingDefinitions(stixEntity.id, args),
    stixRelations: (stixEntity, args) => stixRelations(stixEntity.id, args)
  },
  Mutation: {
    importData: (_, { type, file }) => importData(type, file)
  }
};

export default stixEntityResolvers;
