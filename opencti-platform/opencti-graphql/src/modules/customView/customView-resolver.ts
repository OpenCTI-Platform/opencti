import type { Resolvers } from '../../generated/graphql';
import { addCustomView, customViewDelete, getCustomViewById, getCustomViewsContext, getCustomViewsSettings } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customViewDisplay: (_parent, { id }, context) => getCustomViewById(context, context.user, id),
    customViewsDisplayContext: (_parent, _args, context) => getCustomViewsContext(context, context.user),
    customViewsSettings: (_parent, { entityType, options }, context) => getCustomViewsSettings(context, context.user, entityType, options),
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
