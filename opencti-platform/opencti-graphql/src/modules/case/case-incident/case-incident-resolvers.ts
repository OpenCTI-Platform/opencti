import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_OBJECT_ASSIGNEE } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import {
  addCaseIncident,
  caseIncidentContainsStixObjectOrStixRelationship,
  findCaseIncidentPaginated,
  findById,
} from './case-incident-domain';
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
    // Flat storage: custom fields are stored as x_opencti_cf_<name> at root of the ES document
    customFieldValues: (caseIncident: any) => Object.keys(caseIncident)
      .filter((key) => key.startsWith('x_opencti_cf_'))
      .map((key) => {
        const rawVal = caseIncident[key];
        const isNumeric = typeof rawVal === 'number';
        return {
          field_id: key,
          field_name: key,
          int_value: isNumeric ? rawVal : undefined,
          string_value: !isNumeric ? String(rawVal) : undefined,
          select_value: !isNumeric ? String(rawVal) : undefined,
        };
      }),
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
  },
};

export default caseIncidentResolvers;
