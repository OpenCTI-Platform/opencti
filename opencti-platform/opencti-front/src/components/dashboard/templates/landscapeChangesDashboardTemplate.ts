import type { DashboardTemplate, DashboardTemplateFilter, DashboardTemplateSelection } from './dashboardTemplates';

const THREATS = ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign'];
const ARSENAL = ['Malware', 'Tool'];

const eq = (key: string, values: string[]): DashboardTemplateFilter => ({ key: [key], values, operator: 'eq', mode: 'or' });

// Landscape widgets compare the entities matching the filters over the period of the dashboard (30 days without one)
const scope = (entityTypes: string[]): DashboardTemplateSelection => ({
  label: '',
  perspective: 'entities',
  filters: { mode: 'and', filters: [eq('entity_type', entityTypes)], filterGroups: [] },
});

/**
 * What changed in the threat landscape over the period of the dashboard: the most changed threats,
 * their new techniques and relationships, and the most changed malware, tools and vulnerabilities.
 */
export const landscapeChangesDashboardTemplate: DashboardTemplate = {
  id: 'landscape-changes',
  label: 'Threat landscape changes',
  widgets: [
    {
      id: '08a1d5c0-0008-4e08-a008-000000000001',
      type: 'landscape-top-entities',
      perspective: 'entities',
      parameters: { title: 'Top changed threats' },
      dataSelection: [scope(THREATS)],
      layout: { x: 0, y: 0, w: 6, h: 4 },
    },
    {
      id: '08a1d5c0-0008-4e08-a008-000000000002',
      type: 'landscape-techniques',
      perspective: 'entities',
      parameters: { title: 'New techniques of the threats by tactic' },
      dataSelection: [scope(THREATS)],
      layout: { x: 6, y: 0, w: 6, h: 4 },
    },
    {
      id: '08a1d5c0-0008-4e08-a008-000000000003',
      type: 'landscape-relationships',
      perspective: 'entities',
      parameters: { title: 'New relationships of the threats by type' },
      dataSelection: [scope(THREATS)],
      layout: { x: 0, y: 4, w: 6, h: 4 },
    },
    {
      id: '08a1d5c0-0008-4e08-a008-000000000004',
      type: 'landscape-top-entities',
      perspective: 'entities',
      parameters: { title: 'Top changed malware and tools' },
      dataSelection: [scope(ARSENAL)],
      layout: { x: 6, y: 4, w: 6, h: 4 },
    },
    {
      id: '08a1d5c0-0008-4e08-a008-000000000005',
      type: 'landscape-relationships',
      perspective: 'entities',
      parameters: { title: 'New relationships of malware and tools by type' },
      dataSelection: [scope(ARSENAL)],
      layout: { x: 0, y: 8, w: 6, h: 4 },
    },
    {
      id: '08a1d5c0-0008-4e08-a008-000000000006',
      type: 'landscape-top-entities',
      perspective: 'entities',
      parameters: { title: 'Top changed vulnerabilities' },
      dataSelection: [scope(['Vulnerability'])],
      layout: { x: 6, y: 8, w: 6, h: 4 },
    },
  ],
};
