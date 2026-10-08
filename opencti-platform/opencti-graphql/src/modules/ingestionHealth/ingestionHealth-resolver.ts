import type { IngestionCheck as GqlIngestionCheck, IngestionHealth as GqlIngestionHealth, Resolvers } from '../../generated/graphql';
import { type IngestionHealthConnector, resolveIngestionHealth, resolveIngestionWarnings } from './ingestionHealth-domain';

// Both fields carry @ff(flags: ["INGESTION_HEALTH"], softFail: true):
// with the flag off they resolve to null and these resolvers never run.
// The evaluator uses string unions where codegen emits TS enums with the same runtime values.
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
};

export default ingestionHealthResolvers;
