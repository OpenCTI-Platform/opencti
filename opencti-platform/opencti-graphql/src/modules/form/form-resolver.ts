import type { Resolvers } from '../../generated/graphql';
import { addForm, findAll, findById, formDelete, formEdit, submitForm } from './form-domain';

const formResolvers: Resolvers = {
  Query: {
    form: (_, { id }, context) => findById(context, context.user, id),
    forms: (_, args, context) => findAll(context, context.user, args),
  },
  Form: {},
  Mutation: {
    formAdd: (_, { input }, context) => {
      return addForm(context, context.user, input);
    },
    formFieldPatch: (_, { id, input }, context) => {
      return formEdit(context, context.user, id, input);
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

        const bundle = await submitForm(context, context.user, submission);

        return {
          success: true,
          bundleId: bundle.id,
          message: 'Form submitted successfully',
        };
      } catch (error: any) {
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
