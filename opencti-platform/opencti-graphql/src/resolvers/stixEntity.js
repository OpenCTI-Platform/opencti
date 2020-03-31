import {
  createdByRef,
  findById,
  markingDefinitions,
  reports,
  stixRelations,
  tags,
  externalReferences,
  stixEntityAddRelation,
  stixEntityDeleteRelation,
} from '../domain/stixEntity';
import { fetchEditContext } from '../database/redis';

const stixEntityResolvers = {
  Query: {
    stixEntity: (_, { id }) => findById(id),
  },
  StixEntity: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.observable_value) {
        return 'StixObservable';
      }
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    createdByRef: (stixEntity) => createdByRef(stixEntity.id),
    editContext: (stixEntity) => fetchEditContext(stixEntity.id),
    externalReferences: (stixEntity) => externalReferences(stixEntity.id),
    tags: (stixEntity) => tags(stixEntity.id),
    reports: (stixEntity) => reports(stixEntity.id),
    markingDefinitions: (stixEntity) => markingDefinitions(stixEntity.id),
    stixRelations: (stixEntity, args) => stixRelations(stixEntity.id, args),
  },
  Mutation: {
    stixEntityEdit: (_, { id }, { user }) => ({
      relationAdd: ({ input }) => stixEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixEntityDeleteRelation(user, id, relationId),
    }),
  },
};

export default stixEntityResolvers;
