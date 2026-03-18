import type { Resolvers } from '../../generated/graphql';
import { addCustomView, customViewDelete, findById, findCustomViewsPaginated } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customView: (_, { id }, context) => findById(context, context.user, id),
    customViews: (_, args, context) => findCustomViewsPaginated(context, context.user, args),
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
