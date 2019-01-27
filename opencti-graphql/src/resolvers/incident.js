import {
  addIncident,
  incidentDelete,
  findAll,
  findById
} from '../domain/incident';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
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
    stixRelations: (incident, args) => stixRelations(incident.id, args),
    editContext: auth(incident => fetchEditContext(incident.id))
  },
  Mutation: {
    incidentEdit: auth((_, { id }, { user }) => ({
      delete: () => incidentDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    incidentAdd: auth((_, { input }, { user }) => addIncident(user, input))
  }
};

export default incidentResolvers;
