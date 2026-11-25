import { ENTITY_TYPE_PLAYBOOK } from '../../../../src/modules/playbook/playbook-types';

export const playbookAuthor = { id: '0f6d5b0a-4f4d-4a8b-9c1e-2f6a8d1c3b01', standard_id: 'user--6b1a3c0e-7f2d-5e4a-9b8c-1d2e3f4a5b6c', name: 'Jane' };
export const playbookMarkingId = '3c8f2a1e-5b6d-4e7f-8a9b-0c1d2e3f4a5b';

const definitionOf = (runAs: string) => JSON.stringify({
  nodes: [
    {
      id: 'node-start',
      name: 'Listen knowledge events',
      position: { x: 0, y: 0 },
      component_id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
      configuration: JSON.stringify({ create: true, update: false, delete: false, filters: JSON.stringify({ mode: 'and', filters: [{ key: ['objectMarking'], values: [playbookMarkingId] }], filterGroups: [] }) }),
    },
    {
      id: 'node-agent',
      name: 'Summarize',
      position: { x: 0, y: 150 },
      component_id: 'PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT',
      configuration: JSON.stringify({ run_as: { label: 'Jane', value: runAs }, prompt: 'Summarize' }),
    },
  ],
  links: [{ id: 'link-1', from: { port: 'out', id: 'node-start' }, to: { id: 'node-agent' } }],
});

const playbook = (id: string, name: string, createdAt: string) => ({
  id,
  internal_id: id,
  standard_id: `playbook--${id}`,
  entity_type: ENTITY_TYPE_PLAYBOOK,
  name,
  description: 'Enrich the incoming reports',
  playbook_start: 'node-start',
  playbook_running: true,
  playbook_definition: definitionOf(playbookAuthor.id),
  created_at: createdAt,
});

export const enrichPlaybook = playbook('7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d', 'Enrich reports', '2026-01-01T00:00:00.000Z');
export const enrichPlaybookHomonym = playbook('8b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e', 'Enrich reports', '2026-02-01T00:00:00.000Z');
export const triagePlaybook = playbook('9c3d4e5f-6a7b-4c8d-0e9f-1a2b3c4d5e6f', 'Triage/Phishing', '2026-03-01T00:00:00.000Z');

export const ALL_PLAYBOOKS = [enrichPlaybook, enrichPlaybookHomonym, triagePlaybook];

export const EXPORTED_PLAYBOOK_DEFINITION = definitionOf(playbookAuthor.standard_id);
