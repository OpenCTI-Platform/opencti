import type { Resolvers } from '../../generated/graphql';
import { addCustomView, customViewDelete, getCustomViewById, getCustomViewsContext, getCustomViewsSettings } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customView: (_parent, { id }, context) => getCustomViewById(context, context.user, id),
    customViewsContext: (_parent, _args, context) => getCustomViewsContext(context, context.user),
    customViewsSettings: (_parent, { id }, context) => getCustomViewsSettings(context, context.user, id),
  },
  CustomView: {},
  Mutation: {
    customViewAdd: (_, { input }, context) => {
      return addCustomView(context, context.user, input);
    },
    customViewDelete: (_, { id }, context) => {
      return customViewDelete(context, context.user, id);
    },
  },
};

export default customViewResolver;
