import type { BasicStoreEntityStatusTemplate } from '../../../../src/modules/statusTemplate/statusTemplate-types';

// A status template the platform creates, and a custom one
export const defaultStatusTemplate = {
  id: 'in-progress-template-id',
  internal_id: 'in-progress-template-id',
  standard_id: 'statustemplate--2c3d4e5f-6a7b-5c8d-9e0f-1a2b3c4d5e6f',
  entity_type: 'StatusTemplate',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'IN_PROGRESS',
  color: '#5c7bf5',
} as unknown as BasicStoreEntityStatusTemplate;

export const customStatusTemplate = {
  ...defaultStatusTemplate,
  id: 'escalated-template-id',
  internal_id: 'escalated-template-id',
  standard_id: 'statustemplate--9f8e7d6c-5b4a-5392-8170-6f5e4d3c2b1a',
  name: 'Escalated',
  color: '#e91e63',
} as unknown as BasicStoreEntityStatusTemplate;

export const ALL_STATUS_TEMPLATES = [defaultStatusTemplate, customStatusTemplate];
