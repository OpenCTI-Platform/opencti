import { describe, expect, it } from 'vitest';
import { draftToInput, inputToDraft, type IrEntityOption } from './irConfigTypes';
import aiConfig from './irConfigTypes.ai-config.fixture.json';

// A configuration proposed by the AI assisted creation (an IntelligenceRequirementInput as JSON, recorded from the
// XTM One OpenCTI PIR Builder) opens in the configuration form as a draft, and saves back to the same input.

describe('inputToDraft', () => {
  const entities = new Map<string, IrEntityOption>([
    ['2a2f8a23-9943-4309-8d11-098a65f6a85f', { value: '2a2f8a23-9943-4309-8d11-098a65f6a85f', label: 'SystemA', type: 'System' }],
  ]);

  it('maps every block of the proposal into the draft', () => {
    const draft = inputToDraft(aiConfig, entities);
    expect(draft.name).toBe(aiConfig.name);
    expect(draft.question).toBe(aiConfig.ir_question);
    expect(draft.status).toBe('paused');
    expect(draft.kiqs.map((k) => k.criteria_ids)).toEqual(aiConfig.ir_kiqs.map((k) => k.criteria_ids));
    expect(draft.criteria.map((c) => c.id)).toEqual(aiConfig.ir_scope_criteria.map((c) => c.id));
    expect(draft.rules).toHaveLength(aiConfig.ir_relevance_rules.length);
  });

  it('serializes the filters the form expects as strings', () => {
    const draft = inputToDraft(aiConfig, entities);
    const group = draft.groups.find((g) => g.kind === 'filter');
    expect(typeof group?.filters).toBe('string');
    expect(JSON.parse(group?.filters ?? '{}')).toEqual(aiConfig.ir_subject_groups.find((g) => g.kind === 'filter')?.filters);
  });

  it('round-trips through the form back to an equivalent input', () => {
    const input = draftToInput(inputToDraft(aiConfig, entities));
    expect(input.ir_scope_criteria.map((c) => [c.id, c.kind, c.relationship_types, c.direction, c.target_types, c.mode]))
      .toEqual(aiConfig.ir_scope_criteria.map((c) => [c.id, c.kind, c.kind === 'graph' ? c.relationship_types : [], c.direction, c.target_types, c.mode]));
  });

  it('shows the legacy required rules of a proposal as conditions of the criteria bringing their types', () => {
    const draft = inputToDraft({
      name: 'x',
      ir_question: 'q',
      ir_scope_criteria: [
        { id: 'c-groups', kind: 'graph', target_types: ['Intrusion-Set', 'Campaign'], mode: 'auto' },
        { id: 'c-vulns', kind: 'graph', target_types: ['Vulnerability'], mode: 'auto' },
      ],
      ir_relevance_rules: [
        { id: 'r-eu', name: 'Targets Europe (required)', applies_to_types: ['Intrusion-Set'], points: 0, required: true, path_condition: { relationship_types: ['targets'], direction: 'outgoing', target_relationship_type: 'located-at', target_ids: ['europe'] } },
        { id: 'r-kev', name: 'KEV', applies_to_types: ['Vulnerability'], points: 40 },
      ],
    }, new Map());
    expect(draft.criteria[0].conditions).toMatchObject([{ id: 'r-eu', name: 'Targets Europe', applies_to_types: ['Intrusion-Set'] }]);
    expect(draft.criteria[1].conditions).toEqual([]);
    expect(draft.rules.map((r) => r.id)).toEqual(['r-kev']);
    const input = draftToInput(draft);
    expect(input.ir_scope_criteria[0].conditions[0].path_condition).toEqual({ relationship_types: ['targets'], direction: 'outgoing', target_relationship_type: 'located-at', target_ids: ['europe'], target_group_ids: [] });
  });

  it('names unknown entities by their id and defaults invalid values', () => {
    const draft = inputToDraft({
      name: 'x',
      ir_question: 'q',
      ir_priority: 'urgent',
      ir_subject_groups: [{ id: 'g', name: 'g', kind: 'list', role: 'entry', entity_ids: ['unknown-id'] }],
      ir_scope_criteria: [{ id: 'c', name: 'c', kind: 'graph', direction: 'sideways', mode: 'auto' }],
    }, new Map());
    expect(draft.priority).toBe('medium');
    expect(draft.groups[0].entities[0]).toEqual({ value: 'unknown-id', label: 'unknown-id', type: '' });
    expect(draft.criteria[0].direction).toBe('outgoing');
    expect(draft.thresholds).toBe('50, 80');
  });
});
