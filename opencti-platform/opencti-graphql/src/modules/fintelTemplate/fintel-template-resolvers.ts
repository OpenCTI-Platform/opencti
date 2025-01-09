import type { Resolvers } from '../../generated/graphql';
import { addFintelTemplate, findById, fintelTemplateDelete, fintelTemplateEditField } from './fintelTemplate-domain';

const fintelTemplateResolvers: Resolvers = {
  Query: {
    fintelTemplate: (_, { id }, context) => findById(context, context.user, id),
  },
  Mutation: {
    fintelTemplateAdd: (_, { input }, context) => {
      return addFintelTemplate(context, context.user, input);
    },
    fintelTemplateDelete: (_, { id }, context) => {
      return fintelTemplateDelete(context, context.user, id);
    },
    fintelTemplateFieldPatch: (_, { id, input }, context) => {
      return fintelTemplateEditField(context, context.user, id, input);
    },
  },
};

export default fintelTemplateResolvers;
