import type { Resolvers } from '../../generated/graphql';
import { getCustomViewById, getCustomViewsContext } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customViewDisplay: (_parent, { id }, context) => getCustomViewById(context, context.user, id),
    customViewsDisplayContext: (_parent, _args, context) => getCustomViewsContext(context, context.user),
    // customViewsSettings: (_parent, { id }, context) => getCustomViewsSettings(context, context.user, id),
  },
  CustomView: {},
  Mutation: {},
};

export default customViewResolver;
