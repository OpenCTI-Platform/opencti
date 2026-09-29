import type { IngestionHealth as GqlIngestionHealth, Resolvers } from '../../generated/graphql';
import type { IngestionHealth } from './ingestionHealth-types';
import {
  resolveConnectorIngestionHealth,
  resolveFeedIngestionHealth,
  resolveSyncIngestionHealth,
} from './ingestionHealth-domain';

// The evaluator's types use plain string unions (kept framework-free), while
// codegen emits nominal TS enums for the same values — same strings at
// runtime, so this bridges the two.
const toGeneratedHealth = (health: IngestionHealth | null): GqlIngestionHealth | null => (
  health as unknown as GqlIngestionHealth | null
);

// One place for all seven ingestion source kinds. Every field carries
// @ff(flags: ["INGESTION_HEALTH"], softFail: true), so with the flag off it
// short-circuits to null and none of these resolvers runs.
const ingestionHealthResolver: Resolvers = {
  Connector: {
    ingestion_health: async (connector, _, context) => toGeneratedHealth(
      await resolveConnectorIngestionHealth(context, context.user, connector),
    ),
  },
  IngestionTaxii: {
    ingestion_health: async (feed, _, context) => toGeneratedHealth(
      await resolveFeedIngestionHealth(feed, context, context.user),
    ),
  },
  IngestionTaxiiCollection: {
    ingestion_health: async (feed, _, context) => toGeneratedHealth(
      await resolveFeedIngestionHealth(feed, context, context.user),
    ),
  },
  IngestionRss: {
    ingestion_health: async (feed, _, context) => toGeneratedHealth(
      await resolveFeedIngestionHealth(feed, context, context.user),
    ),
  },
  IngestionCsv: {
    ingestion_health: async (feed, _, context) => toGeneratedHealth(
      await resolveFeedIngestionHealth(feed, context, context.user),
    ),
  },
  IngestionJson: {
    ingestion_health: async (feed, _, context) => toGeneratedHealth(
      await resolveFeedIngestionHealth(feed, context, context.user),
    ),
  },
  Synchronizer: {
    ingestion_health: async (sync, _, context) => toGeneratedHealth(
      await resolveSyncIngestionHealth(sync, context, context.user),
    ),
  },
};

export default ingestionHealthResolver;
