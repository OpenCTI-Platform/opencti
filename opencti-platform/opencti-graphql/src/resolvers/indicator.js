import { addIndicator, findAll, findById, observables } from '../domain/indicator';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
} from '../domain/stixDomainObject';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const indicatorResolvers = {
  Query: {
    indicator: (_, { id }) => findById(id),
    indicators: (_, args) => findAll(args),
  },
  IndicatorsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  IndicatorsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    observablesContains: `${REL_INDEX_PREFIX}observable_refs.internal_id`,
    indicates: `${REL_INDEX_PREFIX}indicates.internal_id`,
  },
  Indicator: {
    observables: (indicator) => observables(indicator.id),
  },
  Mutation: {
    indicatorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    indicatorAdd: (_, { input }, { user }) => addIndicator(user, input),
  },
};

export default indicatorResolvers;
