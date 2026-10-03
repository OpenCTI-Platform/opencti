import type { AttributeDefinition, MappingDefinition, ObjectAttribute } from '../../schema/attribute-definition';
import { GRAPH_CLUSTER_ID_FILTER, GRAPH_DEGREE_FILTER } from '../../utils/filtering/filtering-constants';
import { ENTITY_TYPE_GRAPH_CLUSTER, GRAPH_CLUSTER_KINDS, GRAPH_CLUSTER_SOURCES, GRAPH_FEATURE_FAMILIES, GRAPH_METRICS_ATTRIBUTE } from './graphAnalytics-types';

const featureFamilyMappings: MappingDefinition[] = GRAPH_FEATURE_FAMILIES.map((family) => ({
  name: family,
  label: family,
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
}));

const pendingRunMappings: MappingDefinition[] = [
  { name: 'pending_cluster_id', label: 'Pending graph cluster', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'pending_cluster_size', label: 'Pending graph cluster size', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'pending_cluster_kind', label: 'Pending graph cluster kind', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'pending_betweenness_approx', label: 'Pending approximate betweenness', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'pending_run_id', label: 'Pending graph analytics run', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
];

// Computed by the graph analytics manager and the opencti-analytics process, never edited by users.
// Written through side-channel updates so no stream event and no updated_at change is produced.
export const graphMetricsAttribute: ObjectAttribute = {
  name: GRAPH_METRICS_ATTRIBUTE,
  label: 'Graph metrics',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
  mappings: [
    {
      name: 'degree',
      label: 'Graph degree',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
      associatedFilterKeys: [{ key: GRAPH_DEGREE_FILTER, label: 'Graph degree' }],
    },
    {
      name: 'degree_by_type',
      label: 'Graph degree by relationship type',
      type: 'object',
      format: 'standard',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'relationship_type', label: 'Relationship type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'count', label: 'Count', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      ],
    },
    { name: 'betweenness_approx', label: 'Approximate betweenness', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    {
      name: 'cluster_id',
      label: 'Graph cluster',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_GRAPH_CLUSTER],
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
      associatedFilterKeys: [{ key: GRAPH_CLUSTER_ID_FILTER, label: 'Graph cluster' }],
    },
    { name: 'cluster_size', label: 'Graph cluster size', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'cluster_kind', label: 'Graph cluster kind', type: 'string', format: 'enum', values: [...GRAPH_CLUSTER_KINDS], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'computed_at', label: 'Graph metrics computation date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    // date the entity joined its current cluster (completion of the run that first assigned it), base of the cluster history
    { name: 'cluster_joined_at', label: 'Graph cluster joining date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    // clustering run that wrote cluster_* and betweenness_approx: the latest completed run detaches older assignments
    { name: 'run_id', label: 'Graph analytics run', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    // metrics staged by a run in progress, applied when the run completes
    ...pendingRunMappings,
  ],
};

export const graphClusterAttributes: AttributeDefinition[] = [
  { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  { name: 'cluster_id', label: 'Cluster identifier', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
  { name: 'cluster_kind', label: 'Cluster kind', type: 'string', format: 'enum', values: [...GRAPH_CLUSTER_KINDS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  { name: 'cluster_source', label: 'Cluster source', type: 'string', format: 'enum', values: [...GRAPH_CLUSTER_SOURCES], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  { name: 'members_count', label: 'Members count', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { name: 'representative_ids', label: 'Representative entities', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: false },
  {
    name: 'cluster_features',
    label: 'Cluster shared features',
    type: 'object',
    format: 'standard',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: false,
    mappings: [
      { name: 'family', label: 'Feature family', type: 'string', format: 'enum', values: [...GRAPH_FEATURE_FAMILIES], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      { name: 'ids', label: 'Feature entities', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    ],
  },
  { name: 'promoted_to_ids', label: 'Promoted to', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  { name: 'last_run_id', label: 'Last computation run', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { name: 'last_computed_at', label: 'Last computation date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
];

export const graphSimilarityAttributes: AttributeDefinition[] = [
  { name: 'similarity_entity_id', label: 'Similarity source entity', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'similarity_entity_type', label: 'Similarity source entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'similarity_target_id', label: 'Similarity target entity', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'similarity_target_type', label: 'Similarity target entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'similarity_score', label: 'Similarity score', type: 'numeric', precision: 'float', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'similarity_jaccard', label: 'Similarity weighted Jaccard', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'similarity_structural', label: 'Similarity structural cosine', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  {
    name: 'similarity_shared',
    label: 'Similarity shared evidence',
    type: 'object',
    format: 'standard',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    mappings: featureFamilyMappings,
  },
  { name: 'similarity_computed_at', label: 'Similarity computation date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
];
