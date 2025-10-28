import { addIncident, findIncidentPaginated, findById, incidentsTimeSeries, incidentsTimeSeriesByEntity } from '../domain/incident';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_OBJECT_ASSIGNEE } from '../schema/stixRefRelationship';
import { buildRefRelationKey, INPUT_PARTICIPANT } from '../schema/general';
import { loadThroughDenormalized } from './stix';
import { filterMembersWithUsersOrgs } from '../utils/access';
import { findSecurityCoverageByCoveredId } from '../modules/securityCoverage/securityCoverage-domain';

const incidentResolvers = {
  Query: {
    incident: (_, { id }, context) => findById(context, context.user, id),
    incidents: (_, args, context) => findIncidentPaginated(context, context.user, args),
    incidentsTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return incidentsTimeSeriesByEntity(context, context.user, args);
      }
      return incidentsTimeSeries(context, context.user, args);
    },
  },
  Incident: {
    securityCoverage: (incident, _, context) => findSecurityCoverageByCoveredId(context, context.user, incident.id),
    objectParticipant: async (incident, _, context) => {
      const participants = await loadThroughDenormalized(context, context.user, incident, INPUT_PARTICIPANT, { sortBy: 'user_email' });
      if (!participants) {
        return [];
      }
      return filterMembersWithUsersOrgs(context, context.user, participants);
    }
  },
  IncidentsOrdering: {
    objectAssignee: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
  },
  Mutation: {
    incidentEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({
        input,
        commitMessage,
        references
      }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({
        toId,
        relationship_type: relationshipType
      }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    incidentAdd: (_, { input }, context) => addIncident(context, context.user, input),
  },
};

export default incidentResolvers;
