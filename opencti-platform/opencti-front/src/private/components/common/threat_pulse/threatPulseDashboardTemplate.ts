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

/**
 * The "Sector benchmark" dashboard: the Threat Pulse widgets (trending in the sector, benchmark against the sector
 * median) next to knowledge widgets on the stored community signal of the entities this platform holds.
 */
export const buildSectorBenchmarkDashboard = (t_i18n: (key: string) => string): DashboardManifest => {
  const widgets = [
    toWidget({ type: 'pulse-trending', title: t_i18n('Trending in your sector'), layout: { x: 0, y: 0, w: 6, h: 8 } }),
    toWidget({ type: 'pulse-benchmark', title: t_i18n('Sector benchmark'), layout: { x: 6, y: 0, w: 6, h: 8 } }),
    toWidget({
      type: 'number',
      title: t_i18n('Indicators rising in the community'),
      layout: { x: 0, y: 8, w: 3, h: 2 },
      dataSelection: [selection('', filterGroup(['Indicator'], 'pulse_trend', ['rising']))],
    }),
    toWidget({
      type: 'number',
      title: t_i18n('Threats rising in your sector'),
      layout: { x: 3, y: 8, w: 3, h: 2 },
      dataSelection: [selection('', filterGroup(THREAT_TYPES, 'pulse_sector_trend', ['rising']))],
    }),
    toWidget({
      type: 'donut',
      title: t_i18n('Community prevalence of indicators'),
      layout: { x: 6, y: 8, w: 3, h: 6 },
      dataSelection: [selection('', filterGroup(['Indicator']), { attribute: 'pulse_prevalence' })],
    }),
    toWidget({
      type: 'horizontal-bar',
      title: t_i18n('Community trend of threats'),
      layout: { x: 9, y: 8, w: 3, h: 6 },
      dataSelection: [selection('', filterGroup(THREAT_TYPES), { attribute: 'pulse_trend' })],
    }),
    toWidget({
      type: 'list',
      title: t_i18n('Threats rising in your sector'),
      layout: { x: 0, y: 10, w: 6, h: 8 },
      dataSelection: [selection('', filterGroup(THREAT_TYPES, 'pulse_sector_trend', ['rising']), { number: 10 })],
    }),
    toWidget({
      type: 'line',
      title: t_i18n('Indicators by network first seen'),
      layout: { x: 6, y: 14, w: 6, h: 6 },
      dataSelection: [selection(t_i18n('Indicators'), filterGroup(['Indicator']), { date_attribute: PULSE_DATE_ATTRIBUTE })],
      parameters: { interval: 'week', legend: false },
    }),
  ];
  return {
    config: {},
    widgets: Object.fromEntries(widgets.map((widget) => [widget.id, widget])),
  };
};
