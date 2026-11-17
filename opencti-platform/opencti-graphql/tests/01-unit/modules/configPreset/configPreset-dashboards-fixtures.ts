import type { BasicStoreEntityWorkspace } from '../../../../src/modules/workspace/workspace-types';

// Two dashboards, and an investigation: a workspace too, never exported as a dashboard. The standard id of a workspace is random on every platform.
export const socDashboard = {
  id: 'soc-dashboard-id',
  internal_id: 'soc-dashboard-id',
  standard_id: 'workspace--6d1a6a2b-9d2c-4e4e-8a43-0f5b1f1c2d11',
  entity_type: 'Workspace',
  type: 'dashboard',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'SOC overview',
  description: 'What the SOC watches',
  tags: ['soc'],
  refresh_interval: 300,
  restricted_members: [{ id: 'creator-secret-id', access_right: 'admin' }],
} as unknown as BasicStoreEntityWorkspace;

export const executiveDashboard = {
  ...socDashboard,
  id: 'executive-dashboard-id',
  internal_id: 'executive-dashboard-id',
  standard_id: 'workspace--0b7e8c53-5b0f-4d52-9d3e-3a8f6b1c7a22',
  name: 'Executive summary',
  description: undefined,
  tags: [],
  refresh_interval: undefined,
  restricted_members: [{ id: 'creator-secret-id', access_right: 'admin' }, { id: 'ALL', access_right: 'view' }],
} as unknown as BasicStoreEntityWorkspace;

export const dashboardInvestigation = {
  ...socDashboard,
  id: 'investigation-id',
  internal_id: 'investigation-id',
  standard_id: 'workspace--9a3c2d41-7e5b-4c11-8f20-6c4d5e6f7a33',
  type: 'investigation',
  name: 'Incident 42',
} as unknown as BasicStoreEntityWorkspace;

export const ALL_DASHBOARDS = [socDashboard, executiveDashboard, dashboardInvestigation];
