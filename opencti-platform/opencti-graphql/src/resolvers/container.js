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
} from '../schema/stixRefRelationship';
import { buildRefRelationKey } from '../schema/general';
import { extractEntityRepresentative } from '../database/utils';
import { investigationAddFromContainer } from '../modules/workspace/investigation-domain';

const containerResolvers = {
  Query: {
    container: (_, { id }, context) => findById(context, context.user, id),
    containers: (_, args, context) => findAll(context, context.user, args),
    containersObjectsOfObject: (_, args, context) => containersObjectsOfObject(context, context.user, args),
  },
  Container: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    objects: (container, args, context) => objects(context, context.user, container.id, args),
    relatedContainers: (container, args, context) => relatedContainers(context, context.user, container.id, args),
  },
  ContainersFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT, '*'),
    creator: 'creator_id',
  },
  Mutation: {
    containerEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
      investigationAdd: () => investigationAddFromContainer(context, context.user, id),
    }),
  },
};

export default containerResolvers;
