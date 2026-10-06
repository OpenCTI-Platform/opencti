import type { Widget } from '../../utils/widget/widget';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';

export interface DashboardConfig {
  startDate?: string | null;
  endDate?: string | null;
  relativeDate?: string | null;
  refresh_interval?: number | null;
  allowViewersToEditTimeFilters?: boolean;
  allowViewersToChangeVariables?: boolean;
  allowViewersToSwitchPresets?: boolean;
}

// When used in dashboards widgets must have a layout
export type DashboardWidget = Widget & { layout: NonNullable<Widget['layout']> };

export type DashboardVariableType = 'vocabulary' | 'killChainPhase' | 'entity' | 'entityType' | 'label' | 'user'
  | 'marking' | 'status' | 'group' | 'boolean' | 'numeric' | 'text' | 'date';

export type DashboardVariableRestriction
  = | { mode: 'none' }
    | { mode: 'selection'; values: string[] }
    | { mode: 'filters'; filters: FilterGroup };

interface DashboardVariableBase {
  id: string;
  name: string;
  restriction: DashboardVariableRestriction;
  defaultValue: string | null;
}

export type DashboardVariable = DashboardVariableBase & (
  | { type: 'vocabulary'; vocabularyCategory: string }
  | { type: 'killChainPhase'; killChainName: string }
  | { type: 'entity'; entityTypes: string[] }
  | { type: Exclude<DashboardVariableType, 'vocabulary' | 'killChainPhase' | 'entity'> }
);

export interface DashboardPreset {
  id: string;
  name: string;
  values: Record<string, string>;
  config: Pick<DashboardConfig, 'startDate' | 'endDate' | 'relativeDate'>;
}

export interface DashboardManifest {
  config: DashboardConfig;
  widgets: Record<string, DashboardWidget>;
  variables?: DashboardVariable[];
  presets?: DashboardPreset[];
}

/**
 * Represents the common fields an Entity should have
 * in order to use the Dashboard shared building blocks
 */
export interface DashboardLike {
  id: string;
  manifest: string | undefined | null;
}

export interface ExportableDashboardLike {
  id: string;
  name: string;
}
