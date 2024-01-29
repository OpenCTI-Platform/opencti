import type { Resolvers } from '../../generated/graphql';
import { dataComponentsPaginated, dataSourceAdd, dataSourceDataComponentAdd, dataSourceDataComponentDelete, findAll, findById } from './dataSource-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import type { BasicStoreEntityDataComponent } from '../dataComponent/dataComponent-types';

const dataSourceResolvers: Resolvers = {
  Query: {
    dataSource: (_, { id }, context) => findById(context, context.user, id),
    dataSources: (_, args, context) => findAll(context, context.user, args),
  },
  DataSource: {
    dataComponents: (dataSource, args, context) => dataComponentsPaginated<BasicStoreEntityDataComponent>(context, context.user, dataSource.id, args),
  },
  Mutation: {
    dataSourceAdd: (_, { input }, context) => {
      return dataSourceAdd(context, context.user, input);
    },
    dataSourceDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    dataSourceFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    dataSourceContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    dataSourceContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    dataSourceRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    dataSourceRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
    dataSourceDataComponentAdd: (_, { id, dataComponentId }, context) => {
      return dataSourceDataComponentAdd(context, context.user, id, dataComponentId);
    },
    dataSourceDataComponentDelete: (_, { id, dataComponentId }, context) => {
      return dataSourceDataComponentDelete(context, context.user, id, dataComponentId);
    },
  }
};

export default dataSourceResolvers;
