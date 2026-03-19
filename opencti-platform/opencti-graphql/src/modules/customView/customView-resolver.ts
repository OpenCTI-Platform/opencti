import type { Resolvers } from '../../generated/graphql';
import { getCustomViewById, getCustomViewsContext } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customView: (_parent, { id }, context) => getCustomViewById(context, context.user, id),
    customViewsContext: (_parent, _args, context) => getCustomViewsContext(context, context.user),
  },
  CustomView: {},
  Mutation: {},
};

export default customViewResolver;
