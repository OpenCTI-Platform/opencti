import { createdByRef, findById, markingDefinitions, reports, stixRelations, tags } from '../domain/stixEntity';
import { fetchEditContext } from '../database/redis';

const stixEntityResolvers = {
  Query: {
    stixEntity: (_, { id, isStixId }) => findById(id, isStixId)
  },
  StixEntity: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.observable_value) {
        return 'StixObservable';
      }
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    createdByRef: entity => createdByRef(entity.id),
    editContext: entity => fetchEditContext(entity.id),
    tags: (entity, args) => tags(entity.id, args),
    reports: (entity, args) => reports(entity.id, args),
    markingDefinitions: (stixEntity, args) => markingDefinitions(stixEntity.id, args),
    stixRelations: (stixEntity, args) => stixRelations(stixEntity.id, args)
  }
};

export default stixEntityResolvers;
