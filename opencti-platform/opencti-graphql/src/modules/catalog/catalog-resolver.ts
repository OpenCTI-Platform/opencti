import { findCatalog, findById, findContractBySlug, getCatalogVersionInfo } from './catalog-domain';
import catalogManager from '../../manager/catalogManager';
import type { Resolvers } from '../../generated/graphql';

const catalogResolver: Resolvers = {
  Query: {
    catalog: (_, { id }, context) => {
      return findById(context, context.user, id);
    },
    catalogs: (_, args, context) => {
      return findCatalog(context, context.user);
    },
    catalogVersionInfo: () => {
      return getCatalogVersionInfo();
    },
    contract: (_, { slug }, context) => {
      return findContractBySlug(context, context.user, slug);
    },
  },
  Mutation: {
    refreshCatalog: () => {
      catalogManager.triggerRefreshInBackground();
      return true;
    },
  },
};

export default catalogResolver;
