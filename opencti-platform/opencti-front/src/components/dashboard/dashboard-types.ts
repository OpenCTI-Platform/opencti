import type { Widget } from '../../utils/widget/widget';

export interface DashboardConfig {
  startDate?: string | null;
  endDate?: string | null;
  relativeDate?: string | null;
}

// When used in dashboards widgets must have a layout
export type DashboardWidget = Widget & { layout: NonNullable<Widget['layout']> };

export interface DashboardManifest {
  config: DashboardConfig;
  widgets: Record<string, DashboardWidget>;
}

/**
 * Represents the common fields an Entity should have
 * in order to use the Dashboard shared building blocks
 */
export interface DashboardLike {
  id: string;
  name: string;
  manifest: string | undefined | null;
}
