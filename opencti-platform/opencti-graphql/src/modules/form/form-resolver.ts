import type { Resolvers } from '../../generated/graphql';
import { addForm, findById, findFormPaginated, formDelete, formEditField, formSubmit, generateFormExportConfiguration, importFormConfiguration } from './form-domain';

const formResolvers: Resolvers = {
  Query: {
    form: (_, { id }, context) => findById(context, context.user, id),
    forms: (_, args, context) => findFormPaginated(context, context.user, args),
  },
  Form: {
    toConfigurationExport: (form, _, context) => generateFormExportConfiguration(context, context.user, form),
  },
  Mutation: {
    formAdd: (_, { input }, context) => {
      return addForm(context, context.user, input);
    },
    formFieldPatch: (_, { id, input }, context) => {
      return formEditField(context, context.user, id, input);
    },
    formDelete: (_, { id }, context) => {
      return formDelete(context, context.user, id);
    },
    formSubmit: (_, { input, isDraft }, context) => {
      return formSubmit(context, context.user, input, isDraft);
    },
    formImport: (_, { file }, context) => {
      return importFormConfiguration(context, context.user, file);
    },
  },
};

export default formResolvers;
