import type { Resolvers } from '../../generated/graphql';
import { addSupportPackage, deleteSupportPackage, findAll, findById, requestZipPackage } from './support-domain';

const supportResolvers: Resolvers = {
  Query: {
    supportPackage: (_, { id }, context) => findById(context, context.user, id),
    supportPackages: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    supportPackageAdd: (_, { input }, context) => {
      return addSupportPackage(context, context.user, input);
    },
    supportPackageForceZip: (_, { input }, context) => {
      return requestZipPackage(context, context.user, input);
    },
    supportPackageDelete: (_, { id }, context) => {
      return deleteSupportPackage(context, context.user, id);
    },
  },
};

export default supportResolvers;
