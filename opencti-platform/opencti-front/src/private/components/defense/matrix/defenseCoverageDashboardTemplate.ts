import { v4 as uuid } from 'uuid';
import type { DashboardManifest, DashboardWidget } from '../../../../components/dashboard/dashboard-types';
import type { WidgetDataSelection } from '../../../../utils/widget/widget';
import type { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { DEFENSE_COVERED_LEVEL, DEFENSE_LEVEL_VALIDATED } from './defenseMatrix-utils';

const RULE_PATTERN_TYPES = ['sigma', 'yara', 'snort', 'suricata', 'spl', 'eql', 'esql', 'kuery', 'lucene', 'kql', 'yara-l', 'crowdstrike-ioa'];

const emptyGroup: FilterGroup = { mode: 'and', filters: [], filterGroups: [] };

const filterGroup = (entityType: string, ...filters: Filter[]): FilterGroup => ({
  mode: 'and',
  filters: [{ key: 'entity_type', values: [entityType], operator: 'eq', mode: 'or' }, ...filters],
  filterGroups: [],
});

const selection = (filters: FilterGroup, extra: Partial<WidgetDataSelection> = {}): WidgetDataSelection => ({
  label: '',
  attribute: 'entity_type',
  date_attribute: 'created_at',
  perspective: 'entities',
  isTo: true,
  filters,
  dynamicFrom: emptyGroup,
  dynamicTo: emptyGroup,
  ...extra,
});

interface TemplateWidget {
  type: string;
  title: string;
  layout: { x: number; y: number; w: number; h: number };
  dataSelection?: WidgetDataSelection[];
}

const toWidget = ({ type, title, layout, dataSelection = [] }: TemplateWidget): DashboardWidget => {
  const id = uuid();
  return {
    id,
    type,
    perspective: dataSelection.length > 0 ? 'entities' : null,
    dataSelection,
    parameters: { title },
    layout: { ...layout, i: id, moved: false, static: false },
  } as DashboardWidget;
};

/**
 * The built-in "Defense coverage" dashboard: the defense widgets (coverage by tactic, top uncovered techniques
 * used by threats) next to knowledge widgets on the stored defense level of the attack patterns.
 */
export const buildDefenseCoverageDashboard = (t_i18n: (key: string) => string): DashboardManifest => {
  const widgets = [
    toWidget({ type: 'defense-tactic-coverage', title: t_i18n('Defense coverage by tactic'), layout: { x: 0, y: 0, w: 6, h: 8 } }),
    toWidget({ type: 'defense-top-gaps', title: t_i18n('Top uncovered techniques used by threats'), layout: { x: 6, y: 0, w: 6, h: 8 } }),
    toWidget({
      type: 'number',
      title: t_i18n('Techniques with a deployed detection'),
      layout: { x: 0, y: 8, w: 3, h: 2 },
      dataSelection: [selection(filterGroup('Attack-Pattern', { key: 'defense_level', values: [String(DEFENSE_COVERED_LEVEL)], operator: 'gte', mode: 'or' }))],
    }),
    toWidget({
      type: 'number',
      title: t_i18n('Techniques validated with OpenAEV'),
      layout: { x: 3, y: 8, w: 3, h: 2 },
      dataSelection: [selection(filterGroup('Attack-Pattern', { key: 'defense_level', values: [String(DEFENSE_LEVEL_VALIDATED)], operator: 'eq', mode: 'or' }))],
    }),
    toWidget({
      type: 'donut',
      title: t_i18n('Techniques by defense level'),
      layout: { x: 6, y: 8, w: 3, h: 6 },
      dataSelection: [selection(filterGroup('Attack-Pattern'), { attribute: 'defense_level', number: 5 })],
    }),
    toWidget({
      type: 'horizontal-bar',
      title: t_i18n('Detection rules by pattern type'),
      layout: { x: 9, y: 8, w: 3, h: 6 },
      dataSelection: [selection(
        filterGroup('Indicator', { key: 'pattern_type', values: RULE_PATTERN_TYPES, operator: 'eq', mode: 'or' }),
        { attribute: 'pattern_type', number: 12 },
      )],
    }),
    toWidget({
      type: 'list',
      title: t_i18n('Latest detection rules'),
      layout: { x: 0, y: 10, w: 6, h: 4 },
      dataSelection: [selection(
        filterGroup('Indicator', { key: 'pattern_type', values: RULE_PATTERN_TYPES, operator: 'eq', mode: 'or' }),
        { number: 10, sort_by: 'created_at', sort_mode: 'desc' },
      )],
    }),
  ];
  return {
    config: {},
    widgets: Object.fromEntries(widgets.map((widget) => [widget.id, widget])),
  };
};
