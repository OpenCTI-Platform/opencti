import type { Resolvers } from '../../generated/graphql';
import { addFintelTemplate, findById, fintelTemplateConfigurationImport, fintelTemplateDelete, fintelTemplateEditField, fintelTemplateExport } from './fintelTemplate-domain';

const fintelTemplateResolvers: Resolvers = {
  Query: {
    fintelTemplate: (_, { id }, context) => findById(context, context.user, id),
  },
  FintelTemplate: {
    toConfigurationExport: (fintelTemplate, _, context) => fintelTemplateExport(context, context.user, fintelTemplate),
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
    fintelTemplateConfigurationImport: (_, { file }, context) => {
      return fintelTemplateConfigurationImport(context, context.user, file);
    },
  },
};

export default fintelTemplateResolvers;
