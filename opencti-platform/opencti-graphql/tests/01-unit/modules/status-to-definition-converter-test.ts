import { describe, expect, it } from 'vitest';
import { StatusScope } from '../../../src/generated/graphql';
import { convertStatusToDefinition } from '../../../src/modules/workflow/migration/status-to-definition-converter';
import type { WorkflowSerializedTransition } from '../../../src/modules/workflow/types/workflow-types';
import type { BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../src/types/store';

const buildStatus = (overrides: Partial<BasicWorkflowStatus> = {}): BasicWorkflowStatus => ({
  id: 'status-id',
  entity_type: 'Status',
  standard_id: 'status-id',
  template_id: 'template-id',
  type: 'Incident',
  scope: StatusScope.Global,
  order: 1,
  ...overrides,
} as BasicWorkflowStatus);

const buildTemplate = (overrides: Partial<BasicWorkflowTemplateEntity> = {}): BasicWorkflowTemplateEntity => ({
  id: 'template-id',
  entity_type: 'StatusTemplate',
  standard_id: 'template-id',
  name: 'New',
  color: '#ff0000',
  ...overrides,
} as BasicWorkflowTemplateEntity);

/** Builds a directed reachability map from `transitions` and asserts every state can reach every other state. */
const isFullyConnected = (transitions: WorkflowSerializedTransition[], stateIds: string[]): boolean => stateIds.every((from) => stateIds.every((to) => {
  if (from === to) return true;
  return transitions.some((t) => t.to === to && (Array.isArray(t.from) ? t.from.includes(from) : t.from === from));
}));

describe('convertStatusToDefinition', () => {
  it('converts a well-formed ordered Status[] into a valid definition with empty diagnostics', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
      buildStatus({ id: 's3', template_id: 't3', order: 3 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'New' }),
      buildTemplate({ id: 't2', name: 'In Progress' }),
      buildTemplate({ id: 't3', name: 'Closed' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    expect(byScope[StatusScope.Global]).toBeDefined();
    const { definition, diagnostics } = byScope[StatusScope.Global]!;
    expect(diagnostics).toEqual([]);
    expect(definition.states.map((s) => s.statusId)).toEqual(['t1', 't2', 't3']);
    expect(definition.initialState).toBe('t1');
  });

  it('adds a MISSING_ORDER diagnostic and still produces a best-effort definition when order is missing', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: undefined as unknown as number }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'New' }),
      buildTemplate({ id: 't2', name: 'In Progress' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition, diagnostics } = byScope[StatusScope.Global]!;
    expect(diagnostics).toContainEqual(expect.objectContaining({ type: 'MISSING_ORDER', statusId: 's2' }));
    expect(definition.states).toHaveLength(2);
    expect(definition.states.map((s) => s.statusId)).toEqual(['t1', 't2']);
  });

  it('adds a NAME_CONFLICT diagnostic when two statuses resolve to the same display name', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'Duplicate' }),
      buildTemplate({ id: 't2', name: 'Duplicate' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { diagnostics } = byScope[StatusScope.Global]!;
    expect(diagnostics.filter((d) => d.type === 'NAME_CONFLICT')).toHaveLength(2);
  });

  it('returns two separate byScope entries, never merged, for a mixed-scope entity type', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1, scope: StatusScope.Global }),
      buildStatus({ id: 's2', template_id: 't2', order: 2, scope: StatusScope.Global }),
      buildStatus({ id: 's3', template_id: 't3', order: 1, scope: StatusScope.RequestAccess }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'New' }),
      buildTemplate({ id: 't2', name: 'Closed' }),
      buildTemplate({ id: 't3', name: 'Pending Approval' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    expect(byScope[StatusScope.Global]!.definition.states.map((s) => s.statusId)).toEqual(['t1', 't2']);
    expect(byScope[StatusScope.RequestAccess]!.definition.states.map((s) => s.statusId)).toEqual(['t3']);
  });

  it('synthesizes fully-connected transitions by default (every state reachable from every other state)', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
      buildStatus({ id: 's3', template_id: 't3', order: 3 }),
      buildStatus({ id: 's4', template_id: 't4', order: 4 }),
    ];
    const templates = ['t1', 't2', 't3', 't4'].map((id) => buildTemplate({ id, name: id }));

    const { byScope } = convertStatusToDefinition(statuses, templates);
    const { definition } = byScope[StatusScope.Global]!;

    expect(isFullyConnected(definition.transitions, ['t1', 't2', 't3', 't4'])).toBe(true);
    // Not just adjacent-order pairs: a non-adjacent jump (t1 -> t4) must also be allowed.
    expect(definition.transitions.some((t) => t.to === 't4' && Array.isArray(t.from) && t.from.includes('t1'))).toBe(true);
  });

  it('returns no transitions for a single-state definition', () => {
    const statuses = [buildStatus({ id: 's1', template_id: 't1', order: 1 })];
    const templates = [buildTemplate({ id: 't1', name: 'New' })];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    expect(byScope[StatusScope.Global]!.definition.transitions).toEqual([]);
  });
});
