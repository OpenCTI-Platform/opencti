import type { Resolvers } from '../../generated/graphql';
import {
  resolveConnectorIngestionHealth,
  resolveFeedIngestionHealth,
  resolveSyncIngestionHealth,
} from './ingestionHealth-domain';

// The field is declared on types that live in the legacy `opencti.graphql` and
// in the ingestion modules' own schemas, so only the resolvers are gathered
// here — one place for all seven ingestion source kinds.
//
// Every one of these fields carries @ff(flags: ["INGESTION_HEALTH"],
// softFail: true), so with the flag off the directive short-circuits to null
// and none of these resolvers runs at all.
const ingestionHealthResolver: Resolvers = {
  Connector: {
    ingestion_health: (connector, _, context) => resolveConnectorIngestionHealth(context, context.user, connector),
  },
  IngestionTaxii: { ingestion_health: (feed, _, context) => resolveFeedIngestionHealth(feed, context, context.user) },
  IngestionTaxiiCollection: { ingestion_health: (feed, _, context) => resolveFeedIngestionHealth(feed, context, context.user) },
  IngestionRss: { ingestion_health: (feed, _, context) => resolveFeedIngestionHealth(feed, context, context.user) },
  IngestionCsv: { ingestion_health: (feed, _, context) => resolveFeedIngestionHealth(feed, context, context.user) },
  IngestionJson: { ingestion_health: (feed, _, context) => resolveFeedIngestionHealth(feed, context, context.user) },
  Synchronizer: { ingestion_health: (sync, _, context) => resolveSyncIngestionHealth(sync, context, context.user) },
};

export default ingestionHealthResolver;
