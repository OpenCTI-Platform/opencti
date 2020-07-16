import {
  addXOpenctiIncident,
  findAll,
  findById,
  xOpenctiIncidentsTimeSeries,
  xOpenctiIncidentsTimeSeriesByEntity,
  observables,
} from '../domain/xOpenctiIncident';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const xOpenctiIncidentResolvers = {
  Query: {
    xOpenctiIncident: (_, { id }) => findById(id),
    xOpenctiIncidents: (_, args) => findAll(args),
    xOpenctiIncidentsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return xOpenctiIncidentsTimeSeriesByEntity(args);
      }
      return xOpenctiIncidentsTimeSeries(args);
    },
  },
  XOpenctiIncidentsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  XOpenctiIncidentsFilter: {
    // eslint-disable-next-line no-undef
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  XOpenctiIncident: {
    observables: (incident) => observables(incident.id),
  },
  Mutation: {
    xOpenctiIncidentEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainObjectDeleteRelation(user, id, relationId),
    }),
    xOpenctiIncidentAdd: (_, { input }, { user }) => addXOpenctiIncident(user, input),
  },
};

export default xOpenctiIncidentResolvers;
