import {
  createdByRef,
  findAll,
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
    stixEntity: (_, { id, isStixId }) => findById(id, isStixId),
    stixEntities: (_, args) => findAll(args)
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
    externalReferences: attPatt => externalReferences(attPatt.id),
    tags: entity => tags(entity.id),
    reports: entity => reports(entity.id),
    markingDefinitions: stixEntity => markingDefinitions(stixEntity.id),
    stixRelations: (stixEntity, args) => stixRelations(stixEntity.id, args)
  }
};

export default stixEntityResolvers;
