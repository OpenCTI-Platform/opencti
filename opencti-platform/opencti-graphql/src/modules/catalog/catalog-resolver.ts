import { DECOUPLING_CONNECTOR_VERSIONS, findCatalog, findCatalogFromES, findById, findContractBySlug, getCatalogVersionInfo } from './catalog-domain';
import { findAllCatalogs, findCatalogBySlug, findContractBySlugAndVersion, findLatestContractBySlug } from './catalog-persistence';
import catalogManager from '../../manager/catalogManager';
import { isFeatureEnabled } from '../../config/conf';
import type { Resolvers } from '../../generated/graphql';

const catalogResolver: Resolvers = {
  Query: {
    catalog: (_, { id }, context) => {
      return findById(context, context.user, id);
    },
    catalogs: (_, args, context) => {
      if (isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS)) {
        return findCatalogFromES(context, context.user);
      }
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
