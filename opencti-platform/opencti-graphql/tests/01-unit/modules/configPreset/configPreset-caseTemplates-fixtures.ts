import { buildRefRelationKey } from '../../../../src/schema/general';
import { type BasicStoreEntityCaseTemplate, TEMPLATE_TASK_RELATION } from '../../../../src/modules/case/case-template/case-template-types';
import type { BasicStoreEntityTaskTemplate } from '../../../../src/modules/task/task-template/task-template-types';

// A case template with two tasks, and one with none and no description. The id of a case template is random on every platform.
export const phishingCaseTemplate = {
  id: 'phishing-case-template-id',
  internal_id: 'phishing-case-template-id',
  standard_id: 'case-template--1a80c59c-d839-4984-af04-04f3286d8f89',
  entity_type: 'Case-Template',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Phishing triage',
  description: 'Triage of a phishing report',
} as unknown as BasicStoreEntityCaseTemplate;

export const fraudCaseTemplate = {
  ...phishingCaseTemplate,
  id: 'fraud-case-template-id',
  internal_id: 'fraud-case-template-id',
  standard_id: 'case-template--7c6b5a49-3827-4615-b403-9e8d7c6b5a49',
  name: 'Fraud investigation',
  description: undefined,
} as unknown as BasicStoreEntityCaseTemplate;

export const ALL_CASE_TEMPLATES = [phishingCaseTemplate, fraudCaseTemplate];

// The task templates are read through the relation they have with their case template
const TASK_RELATION_KEY = buildRefRelationKey(TEMPLATE_TASK_RELATION);
export const notifyTask = {
  id: 'notify-task-id',
  internal_id: 'notify-task-id',
  standard_id: 'task-template--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  entity_type: 'Task-Template',
  creator_id: ['creator-secret-id'],
  name: 'Notify users',
  description: undefined,
  [TASK_RELATION_KEY]: [phishingCaseTemplate.id],
} as unknown as BasicStoreEntityTaskTemplate;

export const blockTask = {
  ...notifyTask,
  id: 'block-task-id',
  internal_id: 'block-task-id',
  standard_id: 'task-template--11111111-2222-4333-8444-555555555555',
  name: 'Block sender',
  description: 'Block the sender domain',
} as unknown as BasicStoreEntityTaskTemplate;

export const ALL_TASK_TEMPLATES = [notifyTask, blockTask];
