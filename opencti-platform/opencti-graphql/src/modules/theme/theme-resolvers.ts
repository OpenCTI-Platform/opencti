import type { Resolvers } from '../../generated/graphql';
import { addTheme, deleteTheme, editTheme, findAll, findById, generateThemeExportConfiguration, themeImport } from './theme-domain';

const themeResolvers: Resolvers = {
  Query: {
    theme: (_, { id }, context) => findById(context, id),
    themes: (_, args, context) => findAll(context, args),
  },
  Theme: {
    toConfigurationExport: (theme) => generateThemeExportConfiguration(theme),
  },
  Mutation: {
    themeAdd: (_, { input }, context) => addTheme(context, context.user, input),
    themeDelete: (_, { id }, context) => deleteTheme(context, context.user, id),
    themeFieldPatch: (_, { id, input }, context) => editTheme(context, context.user, id, input),
    themeImport: (_, { file }, context) => themeImport(context, context.user, file),
  },
};

export default themeResolvers;
