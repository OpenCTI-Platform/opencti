import { Promise as BluePromise } from 'bluebird';
import { stixDomainObjectDelete } from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';
import { findAll, findById, upsertTemplateForCase } from './case-domain';
import { caseTasksPaginated } from '../task/task-domain';
import type { BasicStoreEntityTask } from '../task/task-types';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_PARTICIPANT } from '../../schema/general';

const caseResolvers: Resolvers = {
  Query: {
    case: (_, { id }, context) => findById(context, context.user, id),
    cases: (_, args, context) => findAll(context, context.user, args),
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
    objectParticipant: (container, _, context) => loadThroughDenormalized(context, context.user, container, INPUT_PARTICIPANT, { sortBy: 'user_email' }),
  },
  CasesOrdering: {
    creator: 'creator_id',
  },
  Mutation: {
    caseDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    caseSetTemplate: async (_, { id, caseTemplatesId }, context) => {
      await BluePromise.map(caseTemplatesId, (caseTemplateId) => upsertTemplateForCase(context, context.user, id, caseTemplateId));
      return findById(context, context.user, id);
    },
  }
};

export default caseResolvers;
