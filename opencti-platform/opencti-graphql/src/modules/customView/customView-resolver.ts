import type { Resolvers } from '../../generated/graphql';
import { getCustomViewsSettings, getCustomViewByIdForDisplay, getCustomViewsDisplayContext } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customViewDisplay: (_parent, { id }, context) => getCustomViewByIdForDisplay(context, context.user, id),
    customViewsDisplayContext: (_parent, _args, context) => getCustomViewsDisplayContext(context, context.user),
    customViewsSettings: (_parent, { entityType }, context) => getCustomViewsSettings(context, context.user, entityType),
  },
  CustomView: {},
  Mutation: {},
};

export default customViewResolver;
