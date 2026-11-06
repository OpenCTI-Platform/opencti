import type { Resolvers } from '../../generated/graphql';
import type { IngestionHealthFields } from './ingestionHealth-types';
import { toGraphqlIngestionHealth } from './ingestionHealth-checks';
import { getIngestionHealthSettings, ingestionHealthSettingsEdit } from './ingestionHealth-domain';

// Spread into the resolvers of every type carrying an ingestion health.
export const ingestionHealthFieldResolvers = {
  ingestionHealth: (element: IngestionHealthFields & { entity_type: string }) => toGraphqlIngestionHealth(element.ingestion_health, element.entity_type),
};

const ingestionHealthResolvers: Resolvers = {
  Query: {
    ingestionHealthSettings: (_, __, context) => getIngestionHealthSettings(context, context.user!),
  },
  Mutation: {
    ingestionHealthSettingsEdit: (_, { input }, context) => ingestionHealthSettingsEdit(context, context.user!, input),
  },
};

export default ingestionHealthResolvers;
