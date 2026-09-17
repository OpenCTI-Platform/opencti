import type { IngestionHealth as GqlIngestionHealth, Resolvers } from '../../generated/graphql';
import type { IngestionHealth } from './ingestionHealth-types';
import {
  resolveConnectorIngestionHealth,
  resolveFeedIngestionHealth,
  resolveSyncIngestionHealth,
} from './ingestionHealth-domain';

// `ingestionHealth-types.ts` uses plain string unions for every enum-shaped
// field (status, check codes, severities…), on purpose — it keeps the pure
// evaluator framework-free and lets its unit tests assert against string
// literals directly, with no dependency on graphql-codegen output. TS string
// enums are nominal, though, so the evaluator's result does not structurally
// satisfy the generated `Resolvers` return type even though every value is
// one the schema enum accepts. The string values are identical at runtime
// (that agreement is what the unit tests and the .graphql enum both guard),
// so bridging the two here is exactly as safe as that agreement.
const toGeneratedHealth = (health: IngestionHealth | null): GqlIngestionHealth | null => (
  health as unknown as GqlIngestionHealth | null
);

// The field is declared on types that live in the legacy `opencti.graphql` and
// in the ingestion modules' own schemas, so only the resolvers are gathered
// here — one place for all seven ingestion source kinds.
//
// Every one of these fields carries @ff(flags: ["INGESTION_HEALTH"],
// softFail: true), so with the flag off the directive short-circuits to null
// and none of these resolvers runs at all.
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
