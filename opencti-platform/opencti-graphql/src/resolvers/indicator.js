import { addIndicator, findAll, findById, batchObservables } from '../domain/indicator';
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
import { initBatchLoader } from '../database/middleware';

const batchObservablesLoader = initBatchLoader(batchObservables);

const indicatorResolvers = {
  Query: {
    indicator: (_, { id }) => findById(id),
    indicators: (_, args) => findAll(args),
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
