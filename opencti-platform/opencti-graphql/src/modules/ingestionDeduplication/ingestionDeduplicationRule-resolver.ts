import type { Resolvers } from '../../generated/graphql';
import { loadCreator } from '../../database/members';
import {
  addIngestionDeduplicationRule,
  deleteIngestionDeduplicationRule,
  fieldPatchIngestionDeduplicationRule,
  findAllowedTypes,
  findDefaultExcludedFields,
  findDefaultTtl,
  findHashableFields,
  findUserIngestionDeduplicationRules,
  findUserIngestionUsages,
} from './ingestionDeduplicationRule-domain';

const ingestionDeduplicationRuleResolver: Resolvers = {
  Query: {
    ingestionDeduplicationRules: (_, { userId }, context) => findUserIngestionDeduplicationRules(context, userId),
    ingestionDeduplicationAllowedTypes: () => findAllowedTypes(),
    ingestionDeduplicationDefaultTtl: () => findDefaultTtl(),
    ingestionDeduplicationDefaultExcludedFields: () => findDefaultExcludedFields(),
    ingestionDeduplicationFields: (_, { entityType }, __, info) => findHashableFields(info.schema, entityType),
    ingestionDeduplicationUserUsages: (_, { userId }, context) => findUserIngestionUsages(context, context.user, userId),
  },
  IngestionDeduplicationRule: {
    user: (rule, _, context) => loadCreator(context, context.user, rule.user_id),
    excluded_fields: (rule) => rule.excluded_fields ?? [],
  },
  Mutation: {
    ingestionDeduplicationRuleAdd: (_, { input }, context) => {
      return addIngestionDeduplicationRule(context, context.user, input);
    },
    ingestionDeduplicationRuleFieldPatch: (_, { id, input }, context) => {
      return fieldPatchIngestionDeduplicationRule(context, context.user, id, input);
    },
    ingestionDeduplicationRuleDelete: (_, { id }, context) => {
      return deleteIngestionDeduplicationRule(context, context.user, id);
    },
  },
};

export default ingestionDeduplicationRuleResolver;
