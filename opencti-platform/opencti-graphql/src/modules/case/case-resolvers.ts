import { Promise as BluePromise } from 'bluebird';
import { containersObjectsOfObject } from '../../domain/container';
import { stixDomainObjectDelete } from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { findAll, findById, upsertTemplateForCase } from './case-domain';
import { ENTITY_TYPE_CONTAINER_CASE_TASK } from './case-task/case-task-types';

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
    tasks: (current, _, context) => containersObjectsOfObject(context, context.user, { id: current.id, types: [ENTITY_TYPE_CONTAINER_CASE_TASK] }),
  },
  CasesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
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
