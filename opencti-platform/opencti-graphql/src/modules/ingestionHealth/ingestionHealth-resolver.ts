import type { Resolvers } from '../../generated/graphql';
import {
  resolveConnectorIngestionHealth,
  resolveFeedIngestionHealth,
  resolveSyncIngestionHealth,
} from './ingestionHealth-domain';

// The field is declared on types that live in the legacy `opencti.graphql` and
// in the ingestion modules' own schemas, so only the resolvers are gathered
// here — one place for all seven ingestion source kinds.
const ingestionHealthResolver: Resolvers = {
  Connector: {
    ingestion_health: (connector, _, context) => resolveConnectorIngestionHealth(context, context.user, connector),
  },
  IngestionTaxii: { ingestion_health: (feed) => resolveFeedIngestionHealth(feed) },
  IngestionTaxiiCollection: { ingestion_health: (feed) => resolveFeedIngestionHealth(feed) },
  IngestionRss: { ingestion_health: (feed) => resolveFeedIngestionHealth(feed) },
  IngestionCsv: { ingestion_health: (feed) => resolveFeedIngestionHealth(feed) },
  IngestionJson: { ingestion_health: (feed) => resolveFeedIngestionHealth(feed) },
  Synchronizer: { ingestion_health: (sync) => resolveSyncIngestionHealth(sync) },
};

export default ingestionHealthResolver;
