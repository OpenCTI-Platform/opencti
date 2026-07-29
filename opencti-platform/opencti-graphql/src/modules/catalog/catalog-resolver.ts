import { isFeatureEnabled } from '../../config/conf';
import { getCatalogVersionInfo, isCatalogManagerEnabled } from './catalogManager';
import { findCatalogFromES } from './catalog-repository';
import { findCatalog, findById, findContractBySlug } from './catalog-domain';
import { DECOUPLING_CONNECTOR_VERSIONS } from './catalog-constants';
import type { Resolvers } from '../../generated/graphql';

const catalogResolver: Resolvers = {
  Query: {
    catalog: (_: unknown, { id }: { id: string }, context: any) => {
      return findById(context, context.user, id);
    },
    catalogs: (_: unknown, _args: unknown, context: any) => {
      if (isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS) && isCatalogManagerEnabled()) {
        return findCatalogFromES(context, context.user);
      }
      return findCatalog(context, context.user);
    },
    contract: (_: unknown, { slug }: { slug: string }, context: any) => {
      return findContractBySlug(context, context.user, slug);
    },
    catalogVersionInfo: () => {
      return getCatalogVersionInfo();
    },
  },
} as unknown as Resolvers;

export default catalogResolver;
