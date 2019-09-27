import {
  addIncident,
  findAll,
  findById,
  incidentsTimeSeriesByEntity,
  incidentsTimeSeries
} from '../domain/incident';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

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
