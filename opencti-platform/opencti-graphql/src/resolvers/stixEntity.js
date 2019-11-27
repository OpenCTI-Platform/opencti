import {
  createdByRef,
  findById,
  markingDefinitions,
  reports,
  stixRelations,
  tags,
  externalReferences
} from '../domain/stixEntity';
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
    createdByRef: stixEntity => createdByRef(stixEntity.id),
    editContext: stixEntity => fetchEditContext(stixEntity.id),
    externalReferences: stixEntity => externalReferences(stixEntity.id),
    tags: stixEntity => tags(stixEntity.id),
    reports: stixEntity => reports(stixEntity.id),
    markingDefinitions: stixEntity => markingDefinitions(stixEntity.id),
    stixRelations: (stixEntity, args) => stixRelations(stixEntity.id, args)
  }
};

export default stixEntityResolvers;
