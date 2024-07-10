import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_OBJECT_ASSIGNEE } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addCaseIncident, caseIncidentContainsStixObjectOrStixRelationship, findAll, findById } from './case-incident-domain';
import { getAuthorizedMembers } from '../../../utils/authorizedMembers';

const caseIncidentResolvers: Resolvers = {
  Query: {
    caseIncident: (_, { id }, context) => findById(context, context.user, id),
    caseIncidents: (_, args, context) => findAll(context, context.user, args),
    caseIncidentContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseIncidentContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  CaseIncident: {
    authorized_members: (caseIncidentResponse, _, context) => getAuthorizedMembers(context, context.user, caseIncidentResponse),
  },
  CaseIncidentsOrdering: {
    creator: 'creator_id',
    objectAssignee: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
  },
  Mutation: {
    caseIncidentAdd: (_, { input }, context) => {
      return addCaseIncident(context, context.user, input);
    },
    caseIncidentDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
  }
};

export default caseIncidentResolvers;
