import { Promise as BluePromise } from 'bluebird';
import { stixDomainObjectDeleteWithTypeCheck } from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';
import { ENTITY_TYPE_CONTAINER_CASE } from './case-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from './feedback/feedback-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from './case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from './case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from './case-rft/case-rft-types';
import { findCasesPaginated, findById, upsertTemplateForCase } from './case-domain';
import { caseTasksPaginated } from '../task/task-domain';
import type { BasicStoreEntityTask } from '../task/task-types';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_PARTICIPANT } from '../../schema/general';
import { filterMembersWithUsersOrgs } from '../../utils/access';

const caseResolvers: Resolvers = {
  Query: {
    case: (_, { id }, context) => findById(context, context.user, id),
    cases: (_, args, context) => findCasesPaginated(context, context.user, args),
  },
  Case: {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    tasks: (current, args, context) => caseTasksPaginated<BasicStoreEntityTask>(context, context.user, current.id, args),
    objectParticipant: async (container, _, context) => {
      const participants = await loadThroughDenormalized(context, context.user, container, INPUT_PARTICIPANT, { sortBy: 'user_email' });
      if (!participants) {
        return [];
      }
      return filterMembersWithUsersOrgs(context, context.user, participants);
    }
  },
  CasesOrdering: {
    creator: 'creator_id',
  },
  Mutation: {
    caseDelete: (_, { id }, context) => {
      // Accept any case subtype for deletion
      const acceptedCaseTypes = [
        ENTITY_TYPE_CONTAINER_CASE,
        ENTITY_TYPE_CONTAINER_FEEDBACK,
        ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
        ENTITY_TYPE_CONTAINER_CASE_RFI,
        ENTITY_TYPE_CONTAINER_CASE_RFT,
      ];
      return stixDomainObjectDeleteWithTypeCheck(context, context.user, id, acceptedCaseTypes);
    },
    caseSetTemplate: async (_, { id, caseTemplatesId }, context) => {
      await BluePromise.map(caseTemplatesId, (caseTemplateId) => upsertTemplateForCase(context, context.user, id, caseTemplateId));
      return findById(context, context.user, id);
    },
  }
};

export default caseResolvers;
