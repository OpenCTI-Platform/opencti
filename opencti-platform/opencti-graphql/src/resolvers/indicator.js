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
} from '../domain/indicator';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../schema/stixCoreRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader, distributionEntities } from '../database/middleware';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { batchKillChainPhases } from '../domain/stixCoreObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../schema/stixRefRelationship';

const killChainPhasesLoader = batchLoader(batchKillChainPhases);
const batchObservablesLoader = batchLoader(batchObservables);

const indicatorResolvers = {
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
  IndicatorsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    objectContains: buildRefRelationKey(RELATION_OBJECT),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    basedOn: buildRefRelationKey(RELATION_BASED_ON),
    indicates: buildRefRelationKey(RELATION_INDICATES),
    sightedBy: buildRefRelationKey(STIX_SIGHTING_RELATIONSHIP),
    creator: 'creator_id',
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
