import type { Resolvers } from '../../generated/graphql';
import { addTheme, deleteTheme, editTheme, findAll, findById } from './theme-domain';

const themeResolvers: Resolvers = {
  Query: {
    theme: (_, { id }, context) => findById(context, id),
    themes: (_, args, context) => findAll(context, args),
  },
  Mutation: {
    themeAdd: (_, { input }, context) => addTheme(context, context.user, input),
    themeDelete: (_, { id }, context) => deleteTheme(context, context.user, id),
    themeFieldPatch: (_, { id, input }, context) => editTheme(context, context.user, id, input),
  },
};

export default themeResolvers;
