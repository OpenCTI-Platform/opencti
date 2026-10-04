import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_GRAPH_CLUSTER = 'Graph-Cluster';
export const ENTITY_TYPE_GRAPH_SIMILARITY = 'Graph-Similarity';

// Attribute stored on every Stix Core Object. Other innovations read it through soft checks,
// so the attribute name and its sub-fields are a stable contract.
export const GRAPH_METRICS_ATTRIBUTE = 'x_opencti_graph_metrics';

export const GRAPH_CLUSTER_KINDS = ['infrastructure', 'campaign', 'tooling'] as const;
export type GraphClusterKind = typeof GRAPH_CLUSTER_KINDS[number];

export const GRAPH_CLUSTER_SOURCES = ['platform', 'analytics'] as const;
export type GraphClusterSource = typeof GRAPH_CLUSTER_SOURCES[number];

export const GRAPH_FEATURE_FAMILIES = [
  'techniques',
  'tools',
  'malware',
  'infrastructure',
  'victims',
  'certificates',
  'asn',
  'registrar',
  'nameservers',
  'hosting',
  'reports',
  'objects',
] as const;
export type GraphFeatureFamily = typeof GRAPH_FEATURE_FAMILIES[number];

export type GraphFeatureSets = Partial<Record<GraphFeatureFamily, string[]>>;

export type GraphFeatureProfileKind = 'threat' | 'infrastructure' | 'report';

export interface GraphFeatureProfile {
  id: string;
  entity_type: string;
  kind: GraphFeatureProfileKind;
  features: GraphFeatureSets;
  // relationship type -> count, used for the structural (cosine) part of the score
  relation_vector: Record<string, number>;
}

export interface GraphMetricsDegreeByType {
  relationship_type: string;
  count: number;
}

export interface GraphMetrics {
  degree?: number | null;
  degree_by_type?: GraphMetricsDegreeByType[] | null;
  betweenness_approx?: number | null;
  cluster_id?: string | null;
  cluster_size?: number | null;
  cluster_kind?: GraphClusterKind | null;
  cluster_joined_at?: Date | string | null;
  computed_at?: Date | string | null;
  run_id?: string | null;
}

export interface BasicStoreWithGraphMetrics {
  [GRAPH_METRICS_ATTRIBUTE]?: GraphMetrics | null;
}

// region Graph-Similarity (documents of the dedicated similarity index, ids only)
export interface GraphSimilarityDocument {
  internal_id: string;
  entity_type: typeof ENTITY_TYPE_GRAPH_SIMILARITY;
  similarity_entity_id: string;
  similarity_entity_type: string;
  similarity_target_id: string;
  similarity_target_type: string;
  similarity_score: number;
  similarity_jaccard: number;
  similarity_structural: number;
  similarity_shared: GraphFeatureSets;
  similarity_computed_at: string;
}
// endregion

// region Graph-Cluster (internal object)
export interface GraphClusterFeature {
  family: GraphFeatureFamily;
  ids: string[];
}

export interface BasicStoreEntityGraphCluster extends BasicStoreEntity {
  name: string;
  cluster_id: string;
  cluster_kind: GraphClusterKind;
  cluster_source: GraphClusterSource;
  members_count: number;
  representative_ids: string[];
  cluster_features: GraphClusterFeature[];
  promoted_to_ids: string[];
  last_run_id: string;
  last_computed_at: Date;
}

export interface StoreEntityGraphCluster extends StoreEntity {
  name: string;
  cluster_id: string;
  cluster_kind: GraphClusterKind;
  cluster_source: GraphClusterSource;
  members_count: number;
  representative_ids: string[];
  cluster_features: GraphClusterFeature[];
  promoted_to_ids: string[];
  last_run_id: string;
  last_computed_at: Date;
}

export interface StixGraphCluster extends StixObject {
  name: string;
  cluster_id: string;
  cluster_kind: GraphClusterKind;
  cluster_source: GraphClusterSource;
  members_count: number;
  representative_ids: string[];
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}

export interface StoreEntityGraphSimilarity extends StoreEntity {
  similarity_entity_id: string;
  similarity_target_id: string;
  similarity_score: number;
}

export interface StixGraphSimilarity extends StixObject {
  similarity_entity_id: string;
  similarity_target_id: string;
  similarity_score: number;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Path finder
export interface StixPathRaw {
  node_ids: string[];
  relationship_ids: string[];
  relationship_types: string[];
}

export interface StixPathsSearchResult {
  paths: StixPathRaw[];
  max_depth: number;
  depth_reached: number;
  explored_nodes: number;
  explored_relationships: number;
  truncated: boolean;
  timed_out: boolean;
  duration_ms: number;
}
// endregion
