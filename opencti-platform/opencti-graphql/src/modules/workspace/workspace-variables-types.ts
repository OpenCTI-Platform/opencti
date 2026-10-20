import type { FilterGroup } from '../../generated/graphql';

export type DashboardVariableTypeName = 'vocabulary' | 'killChainPhase' | 'entity' | 'entityType' | 'label' | 'user'
  | 'marking' | 'status' | 'group' | 'boolean' | 'numeric' | 'text' | 'date';

export type StoreDashboardVariableRestriction
  = | { mode: 'none' }
    | { mode: 'selection'; values: string[] }
    | { mode: 'filters'; filters: FilterGroup };

interface StoreDashboardVariableBase {
  id: string;
  name: string;
  restriction: StoreDashboardVariableRestriction;
  defaultValue: string | null;
}

export type StoreDashboardVariable = StoreDashboardVariableBase & (
  | { type: 'vocabulary'; vocabularyCategory: string }
  | { type: 'killChainPhase'; killChainName: string }
  | { type: 'entity'; entityTypes: string[] }
  | { type: Exclude<DashboardVariableTypeName, 'vocabulary' | 'killChainPhase' | 'entity'> }
);

interface StoreDashboardManifestSelection {
  filters?: FilterGroup | null;
  dynamicFrom?: FilterGroup | null;
  dynamicTo?: FilterGroup | null;
}

export interface StoreDashboardManifest {
  config?: Record<string, unknown>;
  widgets?: Record<string, { dataSelection?: StoreDashboardManifestSelection[] }>;
  variables?: StoreDashboardVariable[];
  presets?: unknown[];
}

// Keys only the typed GraphQL API may write: a full manifest sent by a client never overrides them.
export const DASHBOARD_MANIFEST_SERVER_OWNED_KEYS = ['variables', 'presets'] as const;

export const DASHBOARD_VARIABLES_MAX_COUNT = 50;
export const DASHBOARD_VARIABLE_NAME_MAX_LENGTH = 200;
export const DASHBOARD_VARIABLE_SELECTION_MAX_VALUES = 200;
