import { v4 as uuid } from 'uuid';
import type { DashboardManifest, DashboardWidget } from '../../../../components/dashboard/dashboard-types';
import type { WidgetDataSelection } from '../../../../utils/widget/widget';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { PULSE_DATE_ATTRIBUTE } from '../../../../utils/widget/widgetUtils';

const THREAT_TYPES = ['Intrusion-Set', 'Malware', 'Tool'];

const filterGroup = (entityTypes: string[], key?: string, values?: string[]): FilterGroup => ({
  mode: 'and',
  filters: [
    { key: 'entity_type', values: entityTypes, operator: 'eq', mode: 'or' },
    ...(key && values ? [{ key, values, operator: 'eq', mode: 'or' }] : []),
  ],
  filterGroups: [],
});

const selection = (label: string, filters: FilterGroup, extra: Partial<WidgetDataSelection> = {}): WidgetDataSelection => ({
  label,
  attribute: 'entity_type',
  date_attribute: 'created_at',
  perspective: 'entities',
  isTo: true,
  filters,
  dynamicFrom: { mode: 'and', filters: [], filterGroups: [] },
  dynamicTo: { mode: 'and', filters: [], filterGroups: [] },
  ...extra,
});

interface TemplateWidget {
  type: string;
  title: string;
  layout: { x: number; y: number; w: number; h: number };
  dataSelection?: WidgetDataSelection[];
  parameters?: DashboardWidget['parameters'];
}

const toWidget = ({ type, title, layout, dataSelection = [], parameters = {} }: TemplateWidget): DashboardWidget => {
  const id = uuid();
  return {
    id,
    type,
    perspective: dataSelection.length > 0 ? 'entities' : null,
    dataSelection,
    parameters: { ...parameters, title },
    layout: { ...layout, i: id, moved: false, static: false },
  };
};

// `fullOnly`: the widget reads an attribute the preview never writes (sector trend, network first seen), so it would
// show an empty or zero value instead of naming what contributing unlocks.
// The trend and prevalence are the latest community statistics stored on each object, not a period of the objects:
// titles name the measure only, as the dashboard dates bound the objects by their creation.
const sectorBenchmarkWidgets = (t_i18n: (key: string) => string): Array<TemplateWidget & { fullOnly?: boolean }> => [
  { type: 'pulse-trending', title: t_i18n('Objects trending in your sector'), layout: { x: 0, y: 0, w: 6, h: 8 } },
  { type: 'pulse-benchmark', title: t_i18n('Activity of this platform against the sector median'), layout: { x: 6, y: 0, w: 6, h: 8 } },
  {
    type: 'number',
    title: t_i18n('Indicators with a rising community trend'),
    layout: { x: 0, y: 8, w: 3, h: 2 },
    dataSelection: [selection('', filterGroup(['Indicator'], 'pulse_trend', ['rising']))],
  },
  {
    type: 'number',
    title: t_i18n('Threats with a rising sector trend'),
    layout: { x: 3, y: 8, w: 3, h: 2 },
    dataSelection: [selection('', filterGroup(THREAT_TYPES, 'pulse_sector_trend', ['rising']))],
    fullOnly: true,
  },
  {
    type: 'donut',
    title: t_i18n('Community prevalence of indicators'),
    layout: { x: 6, y: 8, w: 3, h: 6 },
    dataSelection: [selection('', filterGroup(['Indicator']), { attribute: 'pulse_prevalence' })],
  },
  {
    type: 'horizontal-bar',
    title: t_i18n('Community trend of threats'),
    layout: { x: 9, y: 8, w: 3, h: 6 },
    dataSelection: [selection('', filterGroup(THREAT_TYPES), { attribute: 'pulse_trend' })],
  },
  {
    type: 'list',
    title: t_i18n('Latest threats with a rising sector trend'),
    layout: { x: 0, y: 10, w: 6, h: 8 },
    dataSelection: [selection('', filterGroup(THREAT_TYPES, 'pulse_sector_trend', ['rising']), { number: 10, sort_by: 'created_at', sort_mode: 'desc' })],
    fullOnly: true,
  },
  {
    type: 'line',
    title: t_i18n('Indicators per week of network first seen'),
    layout: { x: 6, y: 14, w: 6, h: 6 },
    dataSelection: [selection(t_i18n('Indicators'), filterGroup(['Indicator']), { date_attribute: PULSE_DATE_ATTRIBUTE })],
    parameters: { interval: 'week', legend: false },
    fullOnly: true,
  },
];

/**
 * The "Sector benchmark" dashboard: the Threat Pulse widgets (trending in the sector, benchmark against the sector
 * median) next to knowledge widgets on the stored community signal of the entities this platform holds. Built in
 * preview, it leaves out the widgets of the full experience (`lockedSectorBenchmarkWidgets` names them).
 */
export const buildSectorBenchmarkDashboard = (t_i18n: (key: string) => string, { preview = false } = {}): DashboardManifest => {
  const widgets = sectorBenchmarkWidgets(t_i18n)
    .filter((widget) => !(preview && widget.fullOnly))
    .map((widget) => toWidget(widget));
  return {
    config: {},
    widgets: Object.fromEntries(widgets.map((widget) => [widget.id, widget])),
  };
};

// The titles of the widgets a dashboard created in preview leaves out: the template card shows them locked.
export const lockedSectorBenchmarkWidgets = (t_i18n: (key: string) => string): string[] => {
  return sectorBenchmarkWidgets(t_i18n).filter((widget) => widget.fullOnly).map((widget) => widget.title);
};
