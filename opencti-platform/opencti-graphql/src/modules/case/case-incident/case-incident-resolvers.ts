import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_OBJECT_ASSIGNEE } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addCaseIncident, caseIncidentContainsStixObjectOrStixRelationship, findCaseIncidentPaginated, findById, removeCaseIncidentCustomFieldValue, setCaseIncidentCustomFieldValue } from './case-incident-domain';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from './case-incident-types';
import { findSecurityCoverageByCoveredId } from '../../securityCoverage/securityCoverage-domain';

const caseIncidentResolvers: Resolvers = {
  Query: {
    caseIncident: (_, { id }, context) => findById(context, context.user, id),
    caseIncidents: (_, args, context) => findCaseIncidentPaginated(context, context.user, args),
    caseIncidentContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseIncidentContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  CaseIncident: {
    securityCoverage: (caseIncident, _, context) => findSecurityCoverageByCoveredId(context, context.user, caseIncident.id),
    customFieldValues: (caseIncident: any) => caseIncident.custom_field_values ?? [],
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
      return stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    },
    caseIncidentSetCustomFieldValue: (_: unknown, { id, fieldId, value }: { id: string; fieldId: string; value: string }, context: any) => {
      return setCaseIncidentCustomFieldValue(context, context.user, id, fieldId, value);
    },
    caseIncidentRemoveCustomFieldValue: (_: unknown, { id, fieldId }: { id: string; fieldId: string }, context: any) => {
      return removeCaseIncidentCustomFieldValue(context, context.user, id, fieldId);
    },
  },
};

export default caseIncidentResolvers;
