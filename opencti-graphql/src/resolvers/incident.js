import {
  addIncident,
  incidentDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  reports,
  incidentEditContext,
  incidentEditField,
  incidentAddRelation,
  incidentDeleteRelation,
} from '../domain/incident';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const incidentResolvers = {
  Query: {
    incident: auth((_, { id }) => findById(id)),
    incidents: auth((_, args) => findAll(args))
  },
  Incident: {
    createdByRef: (incident, args) => createdByRef(incident.id, args),
    markingDefinitions: (incident, args) => markingDefinitions(incident.id, args),
    reports: (incident, args) => reports(incident.id, args),
    editContext: auth(incident => fetchEditContext(incident.id))
  },
  Mutation: {
    incidentEdit: auth((_, { id }, { user }) => ({
      delete: () => incidentDelete(id),
      fieldPatch: ({ input }) => incidentEditField(user, id, input),
      contextPatch: ({ input }) => incidentEditContext(user, id, input),
      relationAdd: ({ input }) => incidentAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        incidentDeleteRelation(user, id, relationId)
    })),
    incidentAdd: auth((_, { input }, { user }) => addIncident(user, input))
  }
};

export default incidentResolvers;
