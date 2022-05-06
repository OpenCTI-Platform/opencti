import { findAll, findById, objects, containersObjectsOfObject, relatedContainers } from '../domain/container';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';

const containerResolvers = {
  Query: {
    container: (_, { id }, { user }) => findById(user, id),
    containers: (_, args, { user }) => findAll(user, args),
    containersObjectsOfObject: (_, args, { user }) => containersObjectsOfObject(user, args),
  },
  Container: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    objects: (container, args, { user }) => objects(user, container.id, args),
    relatedContainers: (container, args, { user }) => relatedContainers(user, container.id, args),
  },
  ContainersFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT),
  },
  Mutation: {
    containerEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
  },
};

export default containerResolvers;
