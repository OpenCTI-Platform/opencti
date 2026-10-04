import type { DashboardTemplate, DashboardTemplateFilterGroup, DashboardTemplateSelection } from './dashboardTemplates';

const THREAT_TYPES = ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign'];
const HUB_THREAT_TYPES = [...THREAT_TYPES, 'Malware'];
const INFRASTRUCTURE_TYPES = ['Infrastructure', 'IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'Hostname', 'Url', 'X509-Certificate'];

const ofTypes = (types: string[]): DashboardTemplateFilterGroup => ({
  mode: 'and',
  filters: types.length > 0 ? [{ key: ['entity_type'], values: types, operator: 'eq', mode: 'or' }] : [],
  filterGroups: [],
});

const HUB_COLUMNS = [
  { attribute: 'entity_type', label: 'Type' },
  { attribute: 'name', label: 'Name' },
  { attribute: 'graph_degree', label: 'Graph degree' },
  { attribute: 'graph_cluster_size', label: 'Graph cluster size' },
];

// Lists ranked by the stored graph degree: users who cannot read every relationship get an explanation instead
const hubs = (label: string, types: string[]): DashboardTemplateSelection => ({
  label,
  perspective: 'entities',
  filters: ofTypes(types),
  number: 10,
  sort_by: 'graph_degree',
  sort_mode: 'desc',
  columns: HUB_COLUMNS,
});

/** Graph analytics overview: cluster growth, look-alike threats and the hubs of the threat and infrastructure graph. */
export const graphAnalyticsDashboardTemplate: DashboardTemplate = {
  id: 'graph-analytics',
  label: 'Graph analytics',
  widgets: [
    {
      id: '0a07d150-0001-4d1a-9a07-000000000001',
      type: 'graph-clusters-size',
      perspective: 'entities',
      parameters: { title: 'Largest clusters - members over time', interval: 'month' },
      dataSelection: [{ label: 'Cluster members', perspective: 'entities', filters: ofTypes([]), number: 10 }],
      layout: { x: 0, y: 0, w: 6, h: 6 },
    },
    {
      id: '0a07d150-0001-4d1a-9a07-000000000002',
      type: 'graph-similarity-matrix',
      perspective: 'entities',
      parameters: { title: 'Similarity of the most connected threats' },
      dataSelection: [{ label: 'Threats', perspective: 'entities', filters: ofTypes(THREAT_TYPES), number: 15 }],
      layout: { x: 6, y: 0, w: 6, h: 6 },
    },
    {
      id: '0a07d150-0001-4d1a-9a07-000000000003',
      type: 'list',
      perspective: 'entities',
      parameters: { title: 'Threat and malware hubs - by degree' },
      dataSelection: [hubs('Threats and malware', HUB_THREAT_TYPES)],
      layout: { x: 0, y: 6, w: 6, h: 4 },
    },
    {
      id: '0a07d150-0001-4d1a-9a07-000000000004',
      type: 'list',
      perspective: 'entities',
      parameters: { title: 'Infrastructure hubs - by degree' },
      dataSelection: [hubs('Infrastructure and observables', INFRASTRUCTURE_TYPES)],
      layout: { x: 6, y: 6, w: 6, h: 4 },
    },
    {
      id: '0a07d150-0001-4d1a-9a07-000000000005',
      type: 'graph-top-hubs',
      perspective: 'entities',
      parameters: { title: 'Top hubs - by degree' },
      dataSelection: [{ label: 'All entities', perspective: 'entities', filters: ofTypes([]), number: 15 }],
      layout: { x: 0, y: 10, w: 12, h: 4 },
    },
  ],
};
