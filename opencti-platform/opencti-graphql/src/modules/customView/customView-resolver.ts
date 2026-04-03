import type { Resolvers } from '../../generated/graphql';
import { getCustomViewByIdForDisplay, getCustomViewsDisplayContext } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customViewDisplay: (_parent, { id }, context) => getCustomViewByIdForDisplay(context, context.user, id),
    customViewsDisplayContext: (_parent, _args, context) => getCustomViewsDisplayContext(context, context.user),
  },
  CustomView: {},
  Mutation: {},
};

export default customViewResolver;
