import type { Resolvers } from '../../generated/graphql';
import { addTemplate, templateDelete, templateEditField } from './template-domain';

const templateResolvers: Resolvers = {
  Query: {
  },
  Template: {
  },
  Mutation: {
    templateAdd: (_, { input }, context) => {
      return addTemplate(context, context.user, input);
    },
    templateDelete: (_, { id }, context) => {
      return templateDelete(context, context.user, id);
    },
    templateFieldPatch: (_, { id, input }, context) => {
      return templateEditField(context, context.user, id, input);
    },
  },
};

export default templateResolvers;
