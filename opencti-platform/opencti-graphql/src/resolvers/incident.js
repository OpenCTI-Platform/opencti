import {
  addIncident,
  findAll,
  findById,
  incidentsTimeSeries,
  incidentsTimeSeriesByEntity,
  observableRefs,
} from '../domain/incident';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
} from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const incidentResolvers = {
  Query: {
    incident: (_, { id }) => findById(id),
    incidents: (_, args) => findAll(args),
    incidentsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return incidentsTimeSeriesByEntity(args);
      }
      return incidentsTimeSeries(args);
    },
  },
  IncidentsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`,
  },
  IncidentsFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
  },
  Incident: {
    observableRefs: (incident) => observableRefs(incident.id),
  },
  Mutation: {
    incidentEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    incidentAdd: (_, { input }, { user }) => addIncident(user, input),
  },
};

export default incidentResolvers;
