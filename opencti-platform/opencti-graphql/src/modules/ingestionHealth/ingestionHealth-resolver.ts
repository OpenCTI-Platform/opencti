import type { AuthContext } from '../../types/user';
import type { IngestionCheck as GqlIngestionCheck, IngestionHealth as GqlIngestionHealth, Resolvers } from '../../generated/graphql';
import {
  type IngestionHealthCache,
  type IngestionHealthConnector,
  type IngestionHealthFeed,
  readIngestionHealthCache,
  resolveFeedIngestionWarnings,
  resolveIngestionHealth,
  resolveIngestionWarnings,
} from './ingestionHealth-domain';

// Every field carries @ff(flags: ["INGESTION_HEALTH"], softFail: true):
// with the flag off they resolve to null and these resolvers never run.
// The evaluator uses string unions where codegen emits TS enums with the same runtime values.
const ingestionHealthCacheResolver = (source: unknown) => {
  return readIngestionHealthCache(source as IngestionHealthCache) as unknown as GqlIngestionHealth;
};

const feedIngestionWarningsResolver = async (source: unknown, _: unknown, context: AuthContext) => {
  return (await resolveFeedIngestionWarnings(context, source as IngestionHealthFeed)) as unknown as GqlIngestionCheck[];
};

// Feeds and syncs: the manager cache only, not evaluated yet, and the configuration warnings
const feedResolvers = { ingestion_health: ingestionHealthCacheResolver, ingestion_warnings: feedIngestionWarningsResolver };

const ingestionHealthResolvers: Resolvers = {
  Connector: {
    // The manager cache only: no Redis on this field, polled by the deployed list
    ingestion_health: (connector) => {
      return resolveIngestionHealth(connector as unknown as IngestionHealthConnector) as unknown as GqlIngestionHealth | null;
    },
    ingestion_warnings: async (connector, _, context) => {
      return (await resolveIngestionWarnings(context, connector as unknown as IngestionHealthConnector)) as unknown as GqlIngestionCheck[] | null;
    },
  },
  IngestionCsv: feedResolvers,
  IngestionJson: feedResolvers,
  IngestionRss: feedResolvers,
  IngestionTaxii: feedResolvers,
  IngestionTaxiiCollection: feedResolvers,
  Synchronizer: feedResolvers,
};

export default ingestionHealthResolvers;
