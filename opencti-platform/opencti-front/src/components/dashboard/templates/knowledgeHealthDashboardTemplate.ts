import type { DashboardTemplate } from './dashboardTemplates';

/** "Knowledge health": the score of the curated graph, its trend and the open curation work, from the catalog widgets. */
export const knowledgeHealthDashboardTemplate: DashboardTemplate = {
  id: 'knowledge-health',
  label: 'Knowledge health',
  widgets: [
    {
      id: '0a05c0de-0001-4c05-9a05-000000000001',
      type: 'knowledge-health-score',
      perspective: null,
      parameters: { title: 'Knowledge health score' },
      dataSelection: [],
      layout: { x: 0, y: 0, w: 4, h: 4 },
    },
    {
      id: '0a05c0de-0001-4c05-9a05-000000000002',
      type: 'curation-open-proposals',
      perspective: null,
      parameters: { title: 'Open curation proposals by kind' },
      dataSelection: [],
      layout: { x: 4, y: 0, w: 8, h: 4 },
    },
    {
      id: '0a05c0de-0001-4c05-9a05-000000000003',
      type: 'knowledge-health-trend',
      perspective: null,
      parameters: { title: 'Knowledge health trend' },
      dataSelection: [],
      layout: { x: 0, y: 4, w: 12, h: 4 },
    },
  ],
};
