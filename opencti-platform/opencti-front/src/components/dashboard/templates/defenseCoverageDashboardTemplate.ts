import type { DashboardTemplate, DashboardTemplateFilter, DashboardTemplateFilterGroup, DashboardTemplateSelection } from './dashboardTemplates';
import { DEFENSE_COVERED_LEVEL, DEFENSE_LEVEL_VALIDATED } from '../../../private/components/defense/matrix/defenseMatrix-utils';

const RULE_PATTERN_TYPES = ['sigma', 'yara', 'snort', 'suricata', 'spl', 'eql', 'esql', 'kuery', 'lucene', 'kql', 'yara-l', 'crowdstrike-ioa'];

const eq = (key: string, values: string[], operator = 'eq'): DashboardTemplateFilter => ({ key: [key], values, operator, mode: 'or' });
const group = (filters: DashboardTemplateFilter[]): DashboardTemplateFilterGroup => ({ mode: 'and', filters, filterGroups: [] });

const entities = (entityType: string, filters: DashboardTemplateFilter[] = [], extra: Partial<DashboardTemplateSelection> = {}): DashboardTemplateSelection => ({
  label: '',
  perspective: 'entities',
  filters: group([eq('entity_type', [entityType]), ...filters]),
  ...extra,
});

const rules = (extra: Partial<DashboardTemplateSelection> = {}) => entities('Indicator', [eq('pattern_type', RULE_PATTERN_TYPES)], extra);

/**
 * The defense widgets (coverage by tactic, top uncovered techniques used by threats) next to knowledge widgets
 * on the stored defense level of the attack patterns and on the detection rules.
 */
export const defenseCoverageDashboardTemplate: DashboardTemplate = {
  id: 'defense-coverage',
  label: 'Defense coverage',
  widgets: [
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000001',
      type: 'defense-tactic-coverage',
      perspective: null,
      parameters: { title: 'Defense coverage by tactic' },
      dataSelection: [],
      layout: { x: 0, y: 0, w: 6, h: 8 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000002',
      type: 'defense-top-gaps',
      perspective: null,
      parameters: { title: 'Top uncovered techniques used by threats' },
      dataSelection: [],
      layout: { x: 6, y: 0, w: 6, h: 8 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000003',
      type: 'number',
      perspective: 'entities',
      parameters: { title: 'Techniques with a deployed detection' },
      dataSelection: [entities('Attack-Pattern', [eq('defense_level', [String(DEFENSE_COVERED_LEVEL)], 'gte')])],
      layout: { x: 0, y: 8, w: 3, h: 2 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000004',
      type: 'number',
      perspective: 'entities',
      parameters: { title: 'Techniques validated with OpenAEV' },
      dataSelection: [entities('Attack-Pattern', [eq('defense_level', [String(DEFENSE_LEVEL_VALIDATED)])])],
      layout: { x: 3, y: 8, w: 3, h: 2 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000005',
      type: 'donut',
      perspective: 'entities',
      parameters: { title: 'Techniques by defense level' },
      dataSelection: [entities('Attack-Pattern', [], { attribute: 'defense_level', number: 5 })],
      layout: { x: 6, y: 8, w: 3, h: 6 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000006',
      type: 'horizontal-bar',
      perspective: 'entities',
      parameters: { title: 'Detection rules by pattern type' },
      dataSelection: [rules({ attribute: 'pattern_type', number: 12 })],
      layout: { x: 9, y: 8, w: 3, h: 6 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000007',
      type: 'list',
      perspective: 'entities',
      parameters: { title: 'Latest detection rules' },
      dataSelection: [rules({ number: 10, sort_by: 'created_at', sort_mode: 'desc' })],
      layout: { x: 0, y: 10, w: 6, h: 4 },
    },
  ],
};
