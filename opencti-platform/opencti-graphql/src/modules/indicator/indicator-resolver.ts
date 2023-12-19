import {
  addIndicator,
  batchObservables,
  findAll,
  findById,
  indicatorsDistributionByEntity,
  indicatorsNumber,
  indicatorsNumberByEntity,
  indicatorsTimeSeries,
  indicatorsTimeSeriesByEntity,
} from './indicator-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../../domain/stixDomainObject';
import { batchLoader, distributionEntities } from '../../database/middleware';
import { batchKillChainPhases } from '../../domain/stixCoreObject';
import type { Resolvers } from '../../generated/graphql';
import { ENTITY_TYPE_INDICATOR } from './indicator-types';

const killChainPhasesLoader = batchLoader(batchKillChainPhases);
const batchObservablesLoader = batchLoader(batchObservables);

const indicatorResolvers: Resolvers = {
  Query: {
    indicator: (_, { id }, context) => findById(context, context.user, id),
    indicators: (_, args, context) => findAll(context, context.user, args),
    indicatorsTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsTimeSeriesByEntity(context, context.user, args);
      }
      return indicatorsTimeSeries(context, context.user, args);
    },
    indicatorsNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsNumberByEntity(context, context.user, args);
      }
      return indicatorsNumber(context, context.user, args);
    },
    indicatorsDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsDistributionByEntity(context, context.user, args);
      }
      return distributionEntities(context, context.user, [ENTITY_TYPE_INDICATOR], args);
    },
  },
  Indicator: {
    killChainPhases: (indicator, _, context) => killChainPhasesLoader.load(indicator.id, context, context.user),
    observables: (indicator, _, context) => batchObservablesLoader.load(indicator.id, context, context.user),
  },
  Mutation: {
    indicatorEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    indicatorAdd: (_, { input }, context) => addIndicator(context, context.user, input),
  },
};

export default indicatorResolvers;
