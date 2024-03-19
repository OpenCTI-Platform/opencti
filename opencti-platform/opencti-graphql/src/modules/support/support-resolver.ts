import type { Resolvers } from '../../generated/graphql';
import { addSupportPackage } from './support-domain';

const supportResolvers: Resolvers = {
  Mutation: {
    supportPackageAdd: (_, { input }, context) => {
      return addSupportPackage(context, context.user, input);
    },
  }
};

export default supportResolvers;
