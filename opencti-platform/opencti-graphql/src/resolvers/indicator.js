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
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';
import { distributionEntities, initBatchLoader } from '../database/middleware';

import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';

const batchObservablesLoader = initBatchLoader(batchObservables);

const indicatorResolvers = {
  Query: {
    indicator: (_, { id }) => findById(id),
    indicators: (_, args) => findAll(args),
    indicatorsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsTimeSeriesByEntity(args);
      }
      return indicatorsTimeSeries(args);
    },
    indicatorsNumber: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsNumberByEntity(args);
      }
      return indicatorsNumber(args);
    },
    indicatorsDistribution: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return indicatorsDistributionByEntity(args);
      }
      return distributionEntities(ENTITY_TYPE_INDICATOR, [], args);
    },
  },
  IndicatorsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    basedOn: `${REL_INDEX_PREFIX}${RELATION_BASED_ON}.internal_id`,
    indicates: `${REL_INDEX_PREFIX}indicates.internal_id`,
  },
  Indicator: {
    observables: (indicator) => batchObservablesLoader.load(indicator.id),
    indicator_types: (indicator) => (indicator.indicator_types ? indicator.indicator_types : ['malicious-activity']),
  },
  Mutation: {
    indicatorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    indicatorAdd: (_, { input }, { user }) => addIndicator(user, input),
  },
};

export default indicatorResolvers;
