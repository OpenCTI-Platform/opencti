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

export const GRAPH_CLUSTER_SOURCE_LABELS: Record<string, string> = {
  platform: 'Platform',
  analytics: 'Analytics process',
};

export const GRAPH_CLUSTERS_PATH = '/dashboard/analyses/clusters';

/** A similarity score in [0, 1] as a rounded percentage. */
export const formatSimilarityScore = (score: number | null | undefined): string => {
  const value = Number.isFinite(score) ? Math.min(1, Math.max(0, score as number)) : 0;
  return `${Math.round(value * 100)}%`;
};

/** Chip severity for a similarity score: stronger similarity, stronger color. */
export const similarityScoreSeverity = (score: number): 'critical' | 'high' | 'medium' | 'low' => {
  if (score >= 0.75) return 'critical';
  if (score >= 0.5) return 'high';
  if (score >= 0.25) return 'medium';
  return 'low';
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
