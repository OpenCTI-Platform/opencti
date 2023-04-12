import type { Resolvers } from '../../generated/graphql';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { batchAttackPatterns, batchDataSource, dataComponentAdd, findAll, findById } from './dataComponent-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import { batchLoader } from '../../database/middleware';

const dataSourceLoader = batchLoader(batchDataSource);
const attackPatternsLoader = batchLoader(batchAttackPatterns);

const dataComponentResolvers: Resolvers = {
  Query: {
    dataComponent: (_, { id }, context) => findById(context, context.user, id),
    dataComponents: (_, args, context) => findAll(context, context.user, args),
  },
  DataComponentsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  DataComponent: {
    dataSource: (dataComponent, _, context) => dataSourceLoader.load(dataComponent.id, context, context.user),
    attackPatterns: (dataComponent, _, context) => attackPatternsLoader.load(dataComponent.id, context, context.user),
  },
  Mutation: {
    dataComponentAdd: (_, { input }, context) => {
      return dataComponentAdd(context, context.user, input);
    },
    dataComponentDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    dataComponentFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    dataComponentContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    dataComponentContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    dataComponentRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    dataComponentRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  }
};

export default dataComponentResolvers;
