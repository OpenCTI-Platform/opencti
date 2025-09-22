import type { Resolvers } from '../../generated/graphql';
import { addForm, findFormPaginated, findById, formDelete, formEditField, submitForm } from './form-domain';
import { logApp } from '../../config/conf';

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
      await formDelete(context, context.user, id);
      return id;
    },
    formSubmit: async (_, { input }, context) => {
      try {
        const submission = {
          formId: input.formId,
          values: JSON.parse(input.values),
          userId: context.user?.id,
        };
        const result = await submitForm(context, context.user, submission);
        return result;
      } catch (error: any) {
        logApp.error('[FORM] Failed to submit', { error });
        return {
          success: false,
          bundleId: null,
          message: error.message || 'Form submission failed',
        };
      }
    },
  },
};

export default formResolvers;
