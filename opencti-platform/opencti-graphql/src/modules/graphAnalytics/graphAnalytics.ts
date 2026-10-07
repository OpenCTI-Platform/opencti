import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import {
  ENTITY_TYPE_GRAPH_CLUSTER,
  ENTITY_TYPE_GRAPH_SIMILARITY,
  type StixGraphCluster,
  type StixGraphSimilarity,
  type StoreEntityGraphCluster,
  type StoreEntityGraphSimilarity,
} from './graphAnalytics-types';
import { convertGraphClusterToStix, convertGraphSimilarityToStix } from './graphAnalytics-converter';
import { graphClusterAttributes, graphSimilarityAttributes } from './graphAnalytics-attributes';

// Clusters are computed (platform manager or opencti-analytics process) and never authored by users.
// The cluster identifier is deterministic, so a recomputation keeps the same internal id.
const GRAPH_CLUSTER_DEFINITION: ModuleDefinition<StoreEntityGraphCluster, StixGraphCluster> = {
  type: {
    id: 'graphCluster',
    name: ENTITY_TYPE_GRAPH_CLUSTER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_GRAPH_CLUSTER]: [{ src: 'cluster_id' }],
    },
    resolvers: {},
  },
  attributes: graphClusterAttributes,
  relations: [],
  representative: (stix: StixGraphCluster) => stix.name,
  converter_2_1: convertGraphClusterToStix,
};

// Similarity rows live in their own index (INDEX_GRAPH_SIMILARITY) and are written in bulk by the manager.
// The type is registered so the strict mapping contains their fields.
const GRAPH_SIMILARITY_DEFINITION: ModuleDefinition<StoreEntityGraphSimilarity, StixGraphSimilarity> = {
  type: {
    id: 'graphSimilarity',
    name: ENTITY_TYPE_GRAPH_SIMILARITY,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_GRAPH_SIMILARITY]: [{ src: 'similarity_entity_id' }, { src: 'similarity_target_id' }],
    },
    resolvers: {},
  },
  attributes: graphSimilarityAttributes,
  relations: [],
  representative: (stix: StixGraphSimilarity) => `${stix.similarity_entity_id} ~ ${stix.similarity_target_id}`,
  converter_2_1: convertGraphSimilarityToStix,
};

registerDefinition(GRAPH_CLUSTER_DEFINITION);
registerDefinition(GRAPH_SIMILARITY_DEFINITION);
