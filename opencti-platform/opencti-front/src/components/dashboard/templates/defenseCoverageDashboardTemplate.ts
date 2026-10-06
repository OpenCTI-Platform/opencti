import { KNOWLEDGE } from '../../../utils/hooks/useGranted';
import type { DashboardTemplate, DashboardTemplateFilter, DashboardTemplateFilterGroup, DashboardTemplateSelection } from './dashboardTemplates';

// The rule pattern types of the detection layer (DEFENSE_RULE_PATTERN_TYPES of the defense coverage module)
export const RULE_PATTERN_TYPES = [
  'sigma',
  'yara',
  'snort',
  'suricata',
  'spl',
  'eql',
  'esql',
  'kuery',
  'lucene',
  'kql',
  'yara-l',
  'crowdstrike-ioa',
  'elastic-rule',
  'sentinel-rule',
  'splunk-rule',
  'tanium-signal',
  'nova',
];

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
 * The defense widgets (coverage by tactic, top uncovered techniques used by threats, techniques by level), whose levels
 * are computed for the reader from the evidences they can access, next to knowledge widgets on the detection rules.
 */
export const defenseCoverageDashboardTemplate: DashboardTemplate = {
  id: 'defense-coverage',
  label: 'Defense coverage',
  // The defense widgets read the knowledge of the platform
  needs: [KNOWLEDGE],
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
      type: 'defense-levels',
      perspective: null,
      parameters: { title: 'Techniques by defense level' },
      dataSelection: [],
      layout: { x: 0, y: 8, w: 6, h: 7 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000006',
      type: 'horizontal-bar',
      perspective: 'entities',
      parameters: { title: 'Detection rules by pattern type' },
      dataSelection: [rules({ attribute: 'pattern_type', number: 12 })],
      layout: { x: 6, y: 8, w: 6, h: 7 },
    },
    {
      id: '0a09d3f0-0001-4d09-9a09-000000000007',
      type: 'list',
      perspective: 'entities',
      parameters: { title: 'Latest detection rules' },
      dataSelection: [rules({ number: 10, sort_by: 'created_at', sort_mode: 'desc' })],
      // The list widget shows every default column: it needs the full width to keep them readable
      layout: { x: 0, y: 15, w: 12, h: 8 },
    },
  ],
};
