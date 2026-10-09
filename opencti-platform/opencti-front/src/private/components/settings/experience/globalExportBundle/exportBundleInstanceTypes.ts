import type { GraphQLTaggedNode } from 'react-relay';

export interface InstanceItem {
  id: string;
  name: string;
}

export interface InstanceConnection {
  edges: ReadonlyArray<{ node: InstanceItem | null } | null> | null;
  pageInfo: { endCursor: string | null; hasNextPage: boolean; globalCount: number | null };
}

export interface ExportInstanceConfig {
  entityType: string;
  label: string;
  group?: string;
  query: GraphQLTaggedNode;
  extraVariables?: Record<string, unknown>;
  extractData: (data: unknown) => InstanceConnection | null | undefined;
}
