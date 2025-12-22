import { Promise as BluePromise } from 'bluebird';
import { stixDomainObjectDelete } from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';
import { ENTITY_TYPE_CONTAINER_CASE } from './case-types';
import { findCasesPaginated, findById, upsertTemplateForCase } from './case-domain';
import { caseTasksPaginated } from '../task/task-domain';
import type { BasicStoreEntityTask } from '../task/task-types';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_PARTICIPANT } from '../../schema/general';
import { filterMembersWithUsersOrgs } from '../../utils/access';
import { storeLoadById } from '../../database/middleware-loader';
import { FunctionalError } from '../../config/errors';

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
    },
  },
  CasesOrdering: {
    creator: 'creator_id',
  },
  Mutation: {
    caseDelete: async (_, { id }, context) => {
      // Load the case to get its actual entity type
      const caseEntity = await storeLoadById(context, context.user, id, ENTITY_TYPE_CONTAINER_CASE);
      if (!caseEntity) {
        throw FunctionalError('Case not found', { id });
      }
      // Use the actual entity type for deletion
      return stixDomainObjectDelete(context, context.user, id, caseEntity.entity_type);
    },
    caseSetTemplate: async (_, { id, caseTemplatesId }, context) => {
      await BluePromise.map(caseTemplatesId, (caseTemplateId) => upsertTemplateForCase(context, context.user, id, caseTemplateId));
      return findById(context, context.user, id);
    },
  },
};

export default caseResolvers;
