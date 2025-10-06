import type { Resolvers } from '../../generated/graphql';
import { addTheme, deleteTheme, fieldPatchTheme, findById, findThemePaginated, themeImport } from './theme-domain';

const themeResolvers: Resolvers = {
  Query: {
    theme: (_, { id }, context) => findById(context, context.user, id),
    themes: (_, args, context) => findThemePaginated(context, context.user, args),
  },
  Theme: {
    // toConfigurationExport: (theme) => generateThemeExportConfiguration(theme),
  },
  Mutation: {
    themeAdd: (_, { input }, context) => {
      return addTheme(context, context.user, input);
    },
    themeDelete: (_, { id }, context) => {
      return deleteTheme(context, context.user, id);
    },
    themeFieldPatch: (_, { id, input }, context) => {
      return fieldPatchTheme(context, context.user, id, input);
    },
    themeImport: (_, { file }, context) => themeImport(context, context.user, file),
  },
};

export default themeResolvers;
