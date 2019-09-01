import {
  addIncident,
  findAll,
  findById,
  incidentsTimeSeriesByEntity,
  incidentsTimeSeries
} from '../domain/incident';
import {
  createdByRef,
  markingDefinitions,
  reports,
  exports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const incidentResolvers = {
  Query: {
    incident: (_, { id }) => findById(id),
    incidents: (_, args) => findAll(args),
    incidentsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return incidentsTimeSeriesByEntity(args);
      }
      return incidentsTimeSeries(args);
    }
  },
  Incident: {
    createdByRef: incident => createdByRef(incident.id),
    markingDefinitions: (incident, args) =>
      markingDefinitions(incident.id, args),
    reports: (incident, args) => reports(incident.id, args),
    exports: (incident, args) => exports(incident.id, args),
    stixRelations: (incident, args) => stixRelations(incident.id, args),
    editContext: incident => fetchEditContext(incident.id)
  },
  Mutation: {
    incidentEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    incidentAdd: (_, { input }, { user }) => addIncident(user, input)
  }
};

export default incidentResolvers;
