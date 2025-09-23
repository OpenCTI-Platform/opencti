import type { Resolvers } from '../../generated/graphql';
import { addForm, findFormPaginated, findById, formDelete, formEditField, formSubmit } from './form-domain';

const formResolvers: Resolvers = {
  Query: {
    form: (_, { id }, context) => findById(context, context.user, id),
    forms: (_, args, context) => findFormPaginated(context, context.user, args),
  },
  Form: {},
  Mutation: {
    formAdd: (_, { input }, context) => {
      return addForm(context, context.user, input);
    },
    formFieldPatch: (_, { id, input }, context) => {
      return formEditField(context, context.user, id, input);
    },
    formDelete: async (_, { id }, context) => {
      return formDelete(context, context.user, id);
    },
    formSubmit: async (_, { input, isDraft }, context) => {
      return formSubmit(context, context.user, input, isDraft);
    },
  },
};

export default formResolvers;
