import { toB64 } from '../../../utils/String';
import { defenseCoverageDashboardTemplate } from './defenseCoverageDashboardTemplate';

export interface DashboardTemplateFilter {
  key: string[];
  values: string[];
  operator?: string;
  mode?: string;
}

export interface DashboardTemplateFilterGroup {
  mode: 'and' | 'or';
  filters: DashboardTemplateFilter[];
  filterGroups: DashboardTemplateFilterGroup[];
}

export interface DashboardTemplateSelection {
  label: string;
  perspective: 'entities' | 'relationships';
  filters: DashboardTemplateFilterGroup;
  attribute?: string;
  date_attribute?: string;
  isTo?: boolean;
  number?: number;
  sort_by?: string;
  sort_mode?: 'asc' | 'desc';
  columns?: { attribute: string; label?: string }[];
}

export interface DashboardTemplateWidget {
  id: string;
  type: string;
  /** Null for the widgets that load their own data and carry no data selection. */
  perspective: 'entities' | 'relationships' | null;
  parameters: { title: string; interval?: string };
  dataSelection: DashboardTemplateSelection[];
  layout: { x: number; y: number; w: number; h: number };
}

export interface DashboardTemplate {
  id: string;
  /** English source string, translated by the menu and used as the dashboard name. */
  label: string;
  /** Widget titles and series labels are English source strings, translated when the dashboard is created. */
  widgets: DashboardTemplateWidget[];
}

/** Built-in dashboard templates offered next to "Import dashboard", in menu order. */
export const DASHBOARD_TEMPLATES: DashboardTemplate[] = [
  defenseCoverageDashboardTemplate,
];

// The import endpoint checks a minimal version (5.12.16), not the running one.
export const DASHBOARD_TEMPLATE_FORMAT_VERSION = '6.0.0';

const EMPTY_GROUP = { mode: 'and', filters: [], filterGroups: [] };

/** The export file of a dashboard built from the template, ready for workspaceConfigurationImport. */
export const buildDashboardTemplateExport = (template: DashboardTemplate, t: (text: string) => string) => {
  const widgets = Object.fromEntries(template.widgets.map((widget) => [widget.id, {
    id: widget.id,
    type: widget.type,
    perspective: widget.perspective,
    parameters: { ...widget.parameters, title: t(widget.parameters.title) },
    dataSelection: widget.dataSelection.map((selection) => ({
      number: 10,
      sort_by: 'created_at',
      sort_mode: 'desc',
      attribute: 'entity_type',
      date_attribute: 'created_at',
      isTo: true,
      dynamicFrom: EMPTY_GROUP,
      dynamicTo: EMPTY_GROUP,
      ...selection,
      label: selection.label ? t(selection.label) : '',
    })),
    layout: { ...widget.layout, i: widget.id, moved: false, static: false },
  }]));
  return {
    openCTI_version: DASHBOARD_TEMPLATE_FORMAT_VERSION,
    type: 'dashboard',
    configuration: {
      name: t(template.label),
      manifest: toB64(JSON.stringify({ widgets, config: {} })),
    },
  };
};

export const buildDashboardTemplateFile = (template: DashboardTemplate, t: (text: string) => string) => {
  const content = JSON.stringify(buildDashboardTemplateExport(template, t));
  return new File([content], `${template.id}.json`, { type: 'application/json' });
};
