import type { Resolvers } from '../../generated/graphql';
import { getCustomViewsSettings, getCustomViewByIdForDisplay, getCustomViewsDisplayContext, computeCustomViewPath } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customViewDisplay: (_parent, { id }, context) => {
      return getCustomViewByIdForDisplay(context, context.user, id);
    },
    customViewsDisplayContext: (_parent, _args, context) => {
      return getCustomViewsDisplayContext(context, context.user);
    },
    customViewsSettings: (_parent, { entityType }, context) => {
      return getCustomViewsSettings(context, context.user, entityType);
    },
  },
  CustomView: {
    path: (customView) => {
      return computeCustomViewPath(customView);
    },
  },
  Mutation: {},
};

export default customViewResolver;
