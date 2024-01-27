import {
  addIndicator,
  findAll,
  findById,
  getDecayDetails,
  indicatorsDistributionByEntity,
  indicatorsNumber,
  indicatorsNumberByEntity,
  indicatorsTimeSeries,
  indicatorsTimeSeriesByEntity,
  observablesPaginated
} from './indicator-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../../domain/stixDomainObject';
import { distributionEntities } from '../../database/middleware';
import type { Resolvers } from '../../generated/graphql';
import { ENTITY_TYPE_INDICATOR } from './indicator-types';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_KILLCHAIN } from '../../schema/general';

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
    killChainPhases: (indicator, _, context) => loadThroughDenormalized(context, context.user, indicator, INPUT_KILLCHAIN),
    observables: (indicator, args, context) => observablesPaginated<any>(context, context.user, indicator.id, args),
    decayLiveDetails: (indicator, _, context) => getDecayDetails(context, context.user, indicator),
  },
  Mutation: {
    indicatorAdd: (_, { input }, context) => addIndicator(context, context.user, input),
    indicatorDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    indicatorFieldPatch: (_, { id, input, commitMessage, references }, context) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
    indicatorContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    indicatorContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    indicatorRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    indicatorRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
  },
};

export default indicatorResolvers;
