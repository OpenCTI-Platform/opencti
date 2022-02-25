import {
  addIndicator,
  findAll,
  findById,
  batchObservables,
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
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../schema/stixCoreRelationship';
import { buildRefRelationKey } from '../schema/general';
import { distributionEntities, batchLoader } from '../database/middleware';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { batchKillChainPhases } from '../domain/stixCoreObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';

const killChainPhasesLoader = batchLoader(batchKillChainPhases);
const batchObservablesLoader = batchLoader(batchObservables);

const indicatorResolvers = {
  Query: {
    indicator: (_, { id }, { user }) => findById(user, id),
    indicators: (_, args, { user }) => findAll(user, args),
    indicatorsTimeSeries: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsTimeSeriesByEntity(user, args);
      }
      return indicatorsTimeSeries(user, args);
    },
    indicatorsNumber: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsNumberByEntity(user, args);
      }
      return indicatorsNumber(user, args);
    },
    indicatorsDistribution: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsDistributionByEntity(user, args);
      }
      return distributionEntities(user, ENTITY_TYPE_INDICATOR, [], args);
    },
  },
  IndicatorsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    basedOn: buildRefRelationKey(RELATION_BASED_ON),
    indicates: buildRefRelationKey(RELATION_INDICATES),
    sightedBy: buildRefRelationKey(STIX_SIGHTING_RELATIONSHIP),
  },
  Indicator: {
    killChainPhases: (indicator, _, { user }) => killChainPhasesLoader.load(indicator.id, user),
    observables: (indicator, _, { user }) => batchObservablesLoader.load(indicator.id, user),
    indicator_types: (indicator) => (indicator.indicator_types ? indicator.indicator_types : ['malicious-activity']),
  },
  Mutation: {
    indicatorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    indicatorAdd: (_, { input }, { user }) => addIndicator(user, input),
  },
};

export default indicatorResolvers;
