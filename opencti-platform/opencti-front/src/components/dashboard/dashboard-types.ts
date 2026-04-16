import type { Widget } from '../../utils/widget/widget';

export interface DashboardConfig {
  startDate?: string | null;
  endDate?: string | null;
  relativeDate?: string;
}

// When used in dashboards widgets must have a layout
export type DashboardWidget = Widget & { layout: NonNullable<Widget['layout']> };

export interface DashboardManifest {
  config: DashboardConfig;
  widgets: Record<string, DashboardWidget>;
}

export interface DashboardLike {
  id: string;
  manifest: string | undefined | null;
}
