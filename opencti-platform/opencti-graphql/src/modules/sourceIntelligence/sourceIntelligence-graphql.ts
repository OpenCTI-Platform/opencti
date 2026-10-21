import { registerGraphqlSchema } from '../../graphql/schema';
import { registerFilterRepresentativesReader } from '../../domain/basicObject';
import sourceIntelligenceTypeDefs from './sourceIntelligence.graphql';
import sourceIntelligenceResolvers from './sourceIntelligence-resolvers';
import { readableSources } from './sourceIntelligence-domain';
import { readableRecommendations } from './sourceIntelligence-recommendations';
import { readableCollectionGaps } from './sourceIntelligence-gaps';
import { ENTITY_TYPE_COLLECTION_GAP, ENTITY_TYPE_SOURCE, ENTITY_TYPE_SOURCE_RECOMMENDATION } from './sourceIntelligence-types';

registerGraphqlSchema({
  schema: sourceIntelligenceTypeDefs,
  resolver: sourceIntelligenceResolvers,
});

registerFilterRepresentativesReader([ENTITY_TYPE_SOURCE], readableSources);
registerFilterRepresentativesReader([ENTITY_TYPE_SOURCE_RECOMMENDATION], readableRecommendations);
registerFilterRepresentativesReader([ENTITY_TYPE_COLLECTION_GAP], readableCollectionGaps);
