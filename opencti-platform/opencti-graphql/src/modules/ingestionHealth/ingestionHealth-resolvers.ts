import type { IngestionHealthFields } from './ingestionHealth-types';
import { toGraphqlIngestionHealth } from './ingestionHealth-checks';

// Spread into the resolvers of every type carrying an ingestion health.
export const ingestionHealthFieldResolvers = {
  ingestionHealth: (element: IngestionHealthFields & { entity_type: string }) => toGraphqlIngestionHealth(element.ingestion_health, element.entity_type),
};
