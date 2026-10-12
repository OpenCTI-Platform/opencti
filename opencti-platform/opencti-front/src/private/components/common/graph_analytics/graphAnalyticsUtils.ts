import { graphql } from 'react-relay';
import { commitMutation, defaultCommitMutation, MESSAGING$ } from '../../../../relay/environment';
import type { graphAnalyticsUtilsRecordPivotMutation$variables } from './__generated__/graphAnalyticsUtilsRecordPivotMutation.graphql';

export type GraphAnalyticsPivotKind = graphAnalyticsUtilsRecordPivotMutation$variables['kind'];

// Entity types with a similarity profile, kept aligned with the platform feature extraction
export const GRAPH_SIMILAR_ENTITY_TYPES = [
  'Intrusion-Set',
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Campaign',
  'Malware',
  'Infrastructure',
  'Domain-Name',
  'Hostname',
  'IPv4-Addr',
  'IPv6-Addr',
  'Url',
  'X509-Certificate',
  'Report',
];

export const isGraphSimilarEntityType = (entityType: string) => GRAPH_SIMILAR_ENTITY_TYPES.includes(entityType);

// i18n keys of the shared evidence families
export const GRAPH_FEATURE_FAMILY_LABELS: Record<string, string> = {
  techniques: 'Techniques',
  tools: 'Tools',
  malware: 'Malware',
  infrastructure: 'Infrastructures',
  victims: 'Victims',
  certificates: 'Certificates',
  asn: 'Autonomous systems',
  registrar: 'Registrars',
  nameservers: 'Name servers',
  hosting: 'Hosting',
  reports: 'Reports',
  objects: 'Contained objects',
};

export const GRAPH_CLUSTER_KIND_LABELS: Record<string, string> = {
  infrastructure: 'Infrastructure cluster',
  campaign: 'Campaign cluster',
  tooling: 'Tooling cluster',
};

const GRAPH_CLUSTER_AROUND_LABELS: Record<string, string> = {
  infrastructure: 'Infrastructure cluster around {name}',
  campaign: 'Campaign cluster around {name}',
  tooling: 'Tooling cluster around {name}',
};

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

export interface GraphClusterLabelSource {
  readonly cluster_kind: string;
  readonly representatives?: ReadonlyArray<{ readonly representative: { readonly main: string } }> | null;
}

/**
 * A cluster is shown under what it holds: its first representative the reader can access. The stored name is built
 * from the cluster identifier only, because it is visible to readers who may not access every member.
 */
export const formatGraphClusterLabel = (t_i18n: Translate, cluster: GraphClusterLabelSource): string => {
  const name = cluster.representatives?.[0]?.representative.main;
  if (name) {
    return t_i18n(GRAPH_CLUSTER_AROUND_LABELS[cluster.cluster_kind] ?? 'Cluster around {name}', { values: { name } });
  }
  return t_i18n(GRAPH_CLUSTER_KIND_LABELS[cluster.cluster_kind] ?? 'Cluster');
};

export const GRAPH_CLUSTER_SOURCE_LABELS: Record<string, string> = {
  platform: 'Platform',
  analytics: 'Analytics process',
};

export const GRAPH_CLUSTERS_PATH = '/dashboard/analyses/clusters';

export type GraphAnalyticsState = 'disabled' | 'analysing' | 'not_analysed' | 'up_to_date';

export const GRAPH_ANALYTICS_STATE_CHIPS: Record<GraphAnalyticsState, { label: string; severity: 'neutral' | 'info' | 'low' }> = {
  disabled: { label: 'Disabled', severity: 'neutral' },
  analysing: { label: 'Analysing', severity: 'info' },
  not_analysed: { label: 'Not analysed yet', severity: 'neutral' },
  up_to_date: { label: 'Up to date', severity: 'low' },
};

interface GraphAnalyticsStateSource {
  readonly manager_enabled: boolean;
  readonly pending_entities: number;
  readonly full_pass_in_progress: boolean;
  readonly last_full_pass_completed_at?: unknown;
  readonly last_full_pass_ended_at?: unknown;
  readonly analytics_process_last_run_at?: unknown;
}

/** One state for the analytics status header: disabled, running (pass or queue), never run, or idle and fresh. */
export const resolveGraphAnalyticsState = (status: GraphAnalyticsStateSource): GraphAnalyticsState => {
  if (!status.manager_enabled) return 'disabled';
  if (status.full_pass_in_progress || status.pending_entities > 0) return 'analysing';
  if (!status.last_full_pass_completed_at && !status.last_full_pass_ended_at && !status.analytics_process_last_run_at) return 'not_analysed';
  return 'up_to_date';
};

/** A similarity score in [0, 1] as a rounded percentage. */
export const formatSimilarityScore = (score: number | null | undefined): string => {
  const value = Number.isFinite(score) ? Math.min(1, Math.max(0, score as number)) : 0;
  return `${Math.round(value * 100)}%`;
};

/** Chip tone for a similarity score: a strong match stands out, without the risk colors a similarity does not mean. */
export const similarityScoreSeverity = (score: number): 'info' | 'neutral' => (score >= 0.5 ? 'info' : 'neutral');

/**
 * Growth series start one period before the first member of any of them: the empty months before the clusters
 * existed carry no information and drown the growth in a flat line.
 */
export const trimLeadingEmptyPeriods = <T extends { value: number }>(series: ReadonlyArray<ReadonlyArray<T>>): T[][] => {
  const firstIndexes = series.map((points) => points.findIndex((point) => point.value > 0)).filter((index) => index >= 0);
  const start = firstIndexes.length > 0 ? Math.max(0, Math.min(...firstIndexes) - 1) : 0;
  return series.map((points) => points.slice(start));
};

const recordPivotMutation = graphql`
  mutation graphAnalyticsUtilsRecordPivotMutation($kind: GraphAnalyticsPivotKind!) {
    graphAnalyticsRecordPivot(kind: $kind)
  }
`;

/**
 * GraphQL errors returned with a mutation payload still reach `onCompleted`: report the first one and tell the caller
 * to stop, so a failed action is never followed by a success message, a navigation or a usage count.
 */
export const reportPayloadErrors = (errors: ReadonlyArray<{ message: string }> | null | undefined): boolean => {
  if (!errors || errors.length === 0) return false;
  MESSAGING$.notifyError(errors[0].message);
  return true;
};

/** Fire-and-forget usage counter of the analyst pivots from graph analytics results. */
export const recordGraphAnalyticsPivot = (kind: GraphAnalyticsPivotKind) => {
  commitMutation({
    ...defaultCommitMutation,
    mutation: recordPivotMutation,
    variables: { kind },
  });
};

export interface GraphPathElement {
  id: string;
  entity_type: string;
}

/** Ids of the entities and relationships of paths, without duplicates, for an investigation. */
export const collectPathElementIds = (paths: ReadonlyArray<{ readonly node_ids: ReadonlyArray<string>; readonly relationship_ids: ReadonlyArray<string> }>) => {
  const ids = new Set<string>();
  paths.forEach((path) => {
    path.node_ids.forEach((id) => ids.add(id));
    path.relationship_ids.forEach((id) => ids.add(id));
  });
  return Array.from(ids);
};

export const GRAPH_TOP_HUBS_DEFAULT = 10;
export const GRAPH_TOP_HUBS_MAX = 50;

export interface GraphTopHubNode {
  readonly id: string;
  readonly entity_type: string;
  readonly representative: { readonly main: string };
  readonly x_opencti_graph_metrics: { readonly degree: number | null | undefined } | null | undefined;
}

/** Bars of the top hubs widget, in the order of the ranking; entities without any relationship are not hubs. */
export const buildGraphTopHubsChart = (nodes: ReadonlyArray<GraphTopHubNode>, seriesName: string) => {
  const hubs = nodes.filter((node) => (node.x_opencti_graph_metrics?.degree ?? 0) > 0);
  return {
    series: [{ name: seriesName, data: hubs.map((node) => ({ x: node.representative.main, y: node.x_opencti_graph_metrics?.degree ?? 0 })) }],
    redirectionUtils: hubs.map((node) => ({ id: node.id, entity_type: node.entity_type })),
  };
};
