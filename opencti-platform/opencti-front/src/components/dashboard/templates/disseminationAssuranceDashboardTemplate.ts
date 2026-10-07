import type { DashboardTemplate, DashboardTemplateFilter, DashboardTemplateFilterGroup, DashboardTemplateSelection } from './dashboardTemplates';

const RELATION_DEPLOYED_ON = 'deployed-on';
const LIVE = ['deployed', 'active'];
const PROVEN = ['detected', 'prevented'];

const eq = (key: string, values: string[], operator = 'eq'): DashboardTemplateFilter => ({ key: [key], values, operator, mode: 'or' });
const group = (filters: DashboardTemplateFilter[], filterGroups: DashboardTemplateFilterGroup[] = [], mode: 'and' | 'or' = 'and'): DashboardTemplateFilterGroup => ({
  mode,
  filters,
  filterGroups,
});
const zeroOrMissing = (key: string) => group([eq(key, ['0']), eq(key, [], 'nil')], [], 'or');

const deployments = (label: string, filters: DashboardTemplateFilter[] = [], extra: Partial<DashboardTemplateSelection> = {}): DashboardTemplateSelection => ({
  label,
  perspective: 'relationships',
  filters: group([eq('relationship_type', [RELATION_DEPLOYED_ON]), ...filters]),
  ...extra,
});

const INDICATOR_COLUMNS = [
  { attribute: 'name', label: 'Name' },
  { attribute: 'pattern_type' },
  { attribute: 'created_at', label: 'Platform creation date' },
  { attribute: 'createdBy' },
  { attribute: 'objectMarking' },
];

// Same filters as the saved lists of the Lists page, with revocation standing for expiry: the indicator
// expiration manager revokes indicators past valid_until, and a template cannot carry a moving date.
const indicators = (label: string, filters: DashboardTemplateFilter[], filterGroups: DashboardTemplateFilterGroup[]): DashboardTemplateSelection => ({
  label,
  perspective: 'entities',
  filters: group([eq('entity_type', ['Indicator']), ...filters], filterGroups),
  columns: INDICATOR_COLUMNS,
});

const DEPLOYMENT_COLUMNS = [
  { attribute: 'from_entity_type', label: 'Source type' },
  { attribute: 'from_relationship_type', label: 'Source name' },
  { attribute: 'to_relationship_type', label: 'Target name' },
  { attribute: 'updated_at', label: 'Modification date' },
];

/**
 * The Dissemination assurance overview as a custom dashboard, built from standard widgets
 * over the filterable attributes of deployed-on relationships and the derived indicator counters.
 */
export const disseminationAssuranceDashboardTemplate: DashboardTemplate = {
  id: 'dissemination-assurance',
  label: 'Dissemination assurance',
  widgets: [
    {
      id: '0a10d150-0001-4d1a-9a10-000000000001',
      type: 'number',
      perspective: 'relationships',
      parameters: { title: 'Live deployments' },
      dataSelection: [deployments('', [eq('deployment_status', LIVE)])],
      layout: { x: 0, y: 0, w: 2, h: 2 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000002',
      type: 'number',
      perspective: 'relationships',
      parameters: { title: 'Pending deployments' },
      dataSelection: [deployments('', [eq('deployment_status', ['pending'])])],
      layout: { x: 2, y: 0, w: 2, h: 2 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000003',
      type: 'number',
      perspective: 'relationships',
      parameters: { title: 'Failed deployments' },
      dataSelection: [deployments('', [eq('deployment_status', ['failed'])])],
      layout: { x: 4, y: 0, w: 2, h: 2 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000004',
      type: 'number',
      perspective: 'relationships',
      parameters: { title: 'Expired deployments' },
      dataSelection: [deployments('', [eq('deployment_status', ['expired'])])],
      layout: { x: 6, y: 0, w: 2, h: 2 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000005',
      type: 'number',
      perspective: 'relationships',
      parameters: { title: 'Validated deployments' },
      dataSelection: [deployments('', [eq('validation_status', PROVEN)])],
      layout: { x: 8, y: 0, w: 2, h: 2 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000006',
      type: 'number',
      perspective: 'relationships',
      parameters: { title: 'Missed validations' },
      dataSelection: [deployments('', [eq('validation_status', ['missed'])])],
      layout: { x: 10, y: 0, w: 2, h: 2 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000007',
      type: 'vertical-bar',
      perspective: 'relationships',
      parameters: { title: 'Deployments by status', interval: 'week' },
      dataSelection: [
        deployments('Live', [eq('deployment_status', LIVE)]),
        deployments('Pending', [eq('deployment_status', ['pending'])]),
        deployments('Failed', [eq('deployment_status', ['failed'])]),
        deployments('Removed', [eq('deployment_status', ['removed'])]),
        deployments('Expired', [eq('deployment_status', ['expired'])]),
      ],
      layout: { x: 0, y: 2, w: 6, h: 4 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000008',
      type: 'line',
      perspective: 'relationships',
      parameters: { title: 'Validations by outcome', interval: 'week' },
      dataSelection: [
        deployments('Prevented', [eq('validation_status', ['prevented'])], { date_attribute: 'last_validation_at' }),
        deployments('Detected', [eq('validation_status', ['detected'])], { date_attribute: 'last_validation_at' }),
        deployments('Missed', [eq('validation_status', ['missed'])], { date_attribute: 'last_validation_at' }),
        deployments('Error', [eq('validation_status', ['error'])], { date_attribute: 'last_validation_at' }),
      ],
      layout: { x: 6, y: 2, w: 6, h: 4 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000009',
      type: 'horizontal-bar',
      perspective: 'relationships',
      parameters: { title: 'Live deployments by security platform' },
      dataSelection: [deployments('', [eq('deployment_status', LIVE)], { attribute: 'internal_id', isTo: true })],
      layout: { x: 0, y: 6, w: 6, h: 4 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000010',
      type: 'horizontal-bar',
      perspective: 'relationships',
      parameters: { title: 'Missed validations by security platform' },
      dataSelection: [deployments('', [eq('validation_status', ['missed'])], { attribute: 'internal_id', isTo: true })],
      layout: { x: 6, y: 6, w: 6, h: 4 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000011',
      type: 'list',
      perspective: 'relationships',
      parameters: { title: 'Latest failed deployments' },
      dataSelection: [deployments('', [eq('deployment_status', ['failed'])], { sort_by: 'updated_at', columns: DEPLOYMENT_COLUMNS })],
      layout: { x: 0, y: 10, w: 6, h: 5 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000012',
      type: 'list',
      perspective: 'entities',
      parameters: { title: 'Deployed but never validated' },
      dataSelection: [indicators('', [eq('deployment_platforms_count', ['0'], 'gt')], [zeroOrMissing('validated_platforms_count')])],
      layout: { x: 6, y: 10, w: 6, h: 5 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000013',
      type: 'list',
      perspective: 'entities',
      parameters: { title: 'Disseminated but not deployed' },
      dataSelection: [indicators('', [eq('deployments_count', ['0'], 'gt'), eq('revoked', ['false'])], [zeroOrMissing('deployment_platforms_count')])],
      layout: { x: 0, y: 15, w: 6, h: 5 },
    },
    {
      id: '0a10d150-0001-4d1a-9a10-000000000014',
      type: 'list',
      perspective: 'entities',
      parameters: { title: 'Expired but still deployed' },
      dataSelection: [indicators('', [], [group(
        [eq('deployment_expired_count', ['0'], 'gt')],
        [group([eq('deployment_platforms_count', ['0'], 'gt'), eq('revoked', ['true'])])],
        'or',
      )])],
      layout: { x: 6, y: 15, w: 6, h: 5 },
    },
  ],
};
