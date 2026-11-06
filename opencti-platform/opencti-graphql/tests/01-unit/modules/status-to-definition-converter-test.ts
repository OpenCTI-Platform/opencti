import { describe, expect, it } from 'vitest';
import { StatusScope } from '../../../src/generated/graphql';
import {
  buildWorkflowMigrationPreviewResult,
  convertRequestAccessGroup,
  convertStatusToDefinition,
  getPublishBlockingDiagnostics,
  pickMigrationScope,
} from '../../../src/modules/workflow/migration/status-to-definition-converter';
import type { WorkflowSerializedTransition } from '../../../src/modules/workflow/types/workflow-types';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';
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
  return transitions.some((t) => t.to === to && t.from === from);
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
    expect(diagnostics).toContainEqual(expect.objectContaining({ type: 'MISSING_ORDER', legacyStatusId: 's2', templateId: 't2' }));
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

  it('does not report a false NAME_CONFLICT when multiple templates have blank/whitespace-only names', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: '' }),
      buildTemplate({ id: 't2', name: '   ' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { diagnostics } = byScope[StatusScope.Global]!;
    expect(diagnostics.filter((d) => d.type === 'NAME_CONFLICT')).toHaveLength(0);
  });

  it('adds a DUPLICATE_ORDER diagnostic when two statuses share the same order in a scope group', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 1 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'New' }),
      buildTemplate({ id: 't2', name: 'In Progress' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { diagnostics } = byScope[StatusScope.Global]!;
    expect(diagnostics.filter((d) => d.type === 'DUPLICATE_ORDER')).toHaveLength(2);
  });

  it('keeps the lowest-order status of a duplicated template and adds a DUPLICATE_TEMPLATE diagnostic for the dropped one', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 3 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
      buildStatus({ id: 's3', template_id: 't1', order: 1 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'New' }),
      buildTemplate({ id: 't2', name: 'Closed' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition, diagnostics } = byScope[StatusScope.Global]!;
    expect(definition.states).toEqual([{ statusId: 't1', order: 0 }, { statusId: 't2', order: 1 }]);
    expect(diagnostics).toEqual([expect.objectContaining({ type: 'DUPLICATE_TEMPLATE', legacyStatusId: 's1', templateId: 't1' })]);
  });

  it('adds a MISSING_TEMPLATE diagnostic when a status references a template that no longer exists', () => {
    const statuses = [buildStatus({ id: 's1', template_id: 't1', order: 1 })];

    const { byScope } = convertStatusToDefinition(statuses, []);

    const { diagnostics } = byScope[StatusScope.Global]!;
    expect(diagnostics).toContainEqual(expect.objectContaining({ type: 'MISSING_TEMPLATE', legacyStatusId: 's1', templateId: 't1' }));
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
    expect(definition.transitions.some((t) => t.to === 't4' && t.from === 't1')).toBe(true);
  });

  it('emits one transition per (from, to) pair with a single-string from, which the engine can match', () => {
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

    const { definition } = convertStatusToDefinition(statuses, templates).byScope[StatusScope.Global]!;

    expect(definition.transitions).toHaveLength(6);
    expect(definition.transitions.every((t) => typeof t.from === 'string' && t.from !== t.to)).toBe(true);
    expect(definition.transitions.filter((t) => t.to === 't3')).toEqual([
      { from: 't1', to: 't3', event: 'MOVE_TO_CLOSED' },
      { from: 't2', to: 't3', event: 'MOVE_TO_CLOSED' },
    ]);
  });

  it('breaks order ties and orders statuses without order by status id, whatever the store order', () => {
    const templates = ['t1', 't2', 't3'].map((id) => buildTemplate({ id, name: id }));
    const statuses = [
      buildStatus({ id: 's-c', template_id: 't3', order: undefined as unknown as number }),
      buildStatus({ id: 's-b', template_id: 't2', order: 1 }),
      buildStatus({ id: 's-a', template_id: 't1', order: 1 }),
    ];

    const forward = convertStatusToDefinition(statuses, templates).byScope[StatusScope.Global]!;
    const reversed = convertStatusToDefinition([...statuses].reverse(), templates).byScope[StatusScope.Global]!;

    expect(forward.definition.states.map((s) => s.statusId)).toEqual(['t1', 't2', 't3']);
    expect(reversed.definition).toEqual(forward.definition);
  });

  it('assigns states a sequential 0-based order matching their final migrated rank', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: undefined as unknown as number }),
      buildStatus({ id: 's3', template_id: 't3', order: 3 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'New' }),
      buildTemplate({ id: 't2', name: 'In Progress' }),
      buildTemplate({ id: 't3', name: 'Closed' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition } = byScope[StatusScope.Global]!;
    // t2 has no legacy order, so it is appended after the ordered ones (see MISSING_ORDER
    // diagnostic test above); its rank here must still be a well-defined, sequential 0-based value.
    expect(definition.states).toEqual([
      { statusId: 't1', order: 0 },
      { statusId: 't3', order: 1 },
      { statusId: 't2', order: 2 },
    ]);
  });

  it('names synthesized transitions after the target status display name, not its id', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'New' }),
      buildTemplate({ id: 't2', name: 'In Progress' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition } = byScope[StatusScope.Global]!;
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't1', event: 'MOVE_TO_NEW' }));
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't2', event: 'MOVE_TO_IN_PROGRESS' }));
  });

  it('falls back to the raw id for the event name when the display name is missing', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, []);

    const { definition } = byScope[StatusScope.Global]!;
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't1', event: 'MOVE_TO_T1' }));
  });

  it('falls back to the raw id for the event name when the display name is blank or whitespace-only', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: '' }),
      buildTemplate({ id: 't2', name: '   ' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition } = byScope[StatusScope.Global]!;
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't1', event: 'MOVE_TO_T1' }));
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't2', event: 'MOVE_TO_T2' }));
  });

  it('keeps event names unique when different display names normalize to the same event', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
      buildStatus({ id: 's3', template_id: 't3', order: 3 }),
      buildStatus({ id: 's4', template_id: 't4', order: 4 }),
    ];
    const templates = [
      buildTemplate({ id: 't1', name: 'In Progress' }),
      buildTemplate({ id: 't2', name: 'In-progress' }),
      buildTemplate({ id: 't3', name: 'In Progress 2' }),
      buildTemplate({ id: 't4', name: 'Done' }),
    ];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition, diagnostics } = byScope[StatusScope.Global]!;
    const eventByTarget = new Map(definition.transitions.map((t) => [t.to, t.event]));
    expect(new Set(eventByTarget.values()).size).toBe(4);
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't1', event: 'MOVE_TO_IN_PROGRESS' }));
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't2', event: 'MOVE_TO_IN_PROGRESS_3' }));
    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't3', event: 'MOVE_TO_IN_PROGRESS_2' }));
    expect(diagnostics).toEqual([]);
  });

  it('trims a non-ASCII name used as is in the event name', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
    ];
    const templates = [buildTemplate({ id: 't1', name: '  进行中  ' }), buildTemplate({ id: 't2', name: 'Done' })];

    const { definition } = convertStatusToDefinition(statuses, templates).byScope[StatusScope.Global]!;

    expect(definition.transitions).toContainEqual(expect.objectContaining({ to: 't1', event: 'MOVE_TO_进行中' }));
  });

  it('keeps event names within the 255-character limit for very long names', () => {
    const longName = 'A'.repeat(300);
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
      buildStatus({ id: 's3', template_id: 't3', order: 3 }),
    ];
    const templates = [buildTemplate({ id: 't1', name: longName }), buildTemplate({ id: 't2', name: `${longName}B` }), buildTemplate({ id: 't3', name: 'Done' })];

    const { definition } = convertStatusToDefinition(statuses, templates).byScope[StatusScope.Global]!;

    expect(definition.transitions.every((t) => t.event.length <= 255)).toBe(true);
    expect(new Set(definition.transitions.map((t) => `${t.to}:${t.event}`)).size).toBe(3);
    expect(new Set(definition.transitions.map((t) => t.event)).size).toBe(3);
  });

  it('returns no transitions for a single-state definition', () => {
    const statuses = [buildStatus({ id: 's1', template_id: 't1', order: 1 })];
    const templates = [buildTemplate({ id: 't1', name: 'New' })];

    const { byScope } = convertStatusToDefinition(statuses, templates);

    expect(byScope[StatusScope.Global]!.definition.transitions).toEqual([]);
  });
});

describe('buildWorkflowMigrationPreviewResult', () => {
  it('shapes byScope into a results array per scope, with hasPublishedVersion false by default', () => {
    const statuses = [buildStatus({ id: 's1', template_id: 't1', order: 1 })];
    const templates = [buildTemplate({ id: 't1', name: 'New' })];
    const { byScope } = convertStatusToDefinition(statuses, templates);

    const result = buildWorkflowMigrationPreviewResult('Incident', byScope);

    expect(result).toEqual({
      entityType: 'Incident',
      results: [
        {
          scope: StatusScope.Global,
          initialState: 't1',
          hasPublishedVersion: false,
          states: [{ statusId: 't1', order: 0 }],
          transitions: [],
          diagnostics: [],
        },
      ],
    });
  });

  it('lists the GLOBAL scope first whatever the byScope insertion order', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1, scope: StatusScope.RequestAccess }),
      buildStatus({ id: 's2', template_id: 't2', order: 1, scope: StatusScope.Global }),
    ];
    const templates = [buildTemplate({ id: 't1', name: 'Pending' }), buildTemplate({ id: 't2', name: 'New' })];
    const { byScope } = convertStatusToDefinition(statuses, templates);

    const result = buildWorkflowMigrationPreviewResult('Incident', byScope);

    expect(result.results.map((r) => r.scope)).toEqual([StatusScope.Global, StatusScope.RequestAccess]);
  });

  it('reports hasPublishedVersion on the GLOBAL scope only', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1, scope: StatusScope.Global }),
      buildStatus({ id: 's2', template_id: 't2', order: 1, scope: StatusScope.RequestAccess }),
    ];
    const templates = [buildTemplate({ id: 't1', name: 'New' }), buildTemplate({ id: 't2', name: 'Pending' })];
    const { byScope } = convertStatusToDefinition(statuses, templates);

    const result = buildWorkflowMigrationPreviewResult('Incident', byScope, true);

    expect(result.results.map((r) => [r.scope, r.hasPublishedVersion])).toEqual([
      [StatusScope.Global, true],
      [StatusScope.RequestAccess, false],
    ]);
  });

  it('returns an empty results array when byScope has no entries', () => {
    expect(buildWorkflowMigrationPreviewResult('Incident', {})).toEqual({ entityType: 'Incident', results: [] });
  });
});

describe('pickMigrationScope', () => {
  it('serialises the GLOBAL scope into a definition payload, keeping states, order and transitions', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1 }),
      buildStatus({ id: 's2', template_id: 't2', order: 2 }),
    ];
    const templates = [buildTemplate({ id: 't1', name: 'New' }), buildTemplate({ id: 't2', name: 'Closed' })];
    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition, diagnostics } = pickMigrationScope('Grouping', byScope);

    expect(definition.initialState).toBe('t1');
    expect(definition.states).toEqual([{ statusId: 't1', order: 0 }, { statusId: 't2', order: 1 }]);
    expect(definition.transitions.map((t) => t.event)).toEqual(['MOVE_TO_NEW', 'MOVE_TO_CLOSED']);
    expect(diagnostics).toEqual([]);
  });

  it('ignores non-GLOBAL scopes', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1, scope: StatusScope.Global }),
      buildStatus({ id: 's2', template_id: 't2', order: 1, scope: StatusScope.RequestAccess }),
    ];
    const templates = [buildTemplate({ id: 't1', name: 'New' }), buildTemplate({ id: 't2', name: 'Pending' })];
    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition } = pickMigrationScope('Grouping', byScope);

    expect(definition.states.map((s) => s.statusId)).toEqual(['t1']);
  });

  it('throws when there is no GLOBAL scope result', () => {
    expect(() => pickMigrationScope('Grouping', {})).toThrow('No legacy statuses to migrate');
  });

  it('picks another scope when asked, keeping the REQUEST_ACCESS path open', () => {
    const statuses = [
      buildStatus({ id: 's1', template_id: 't1', order: 1, scope: StatusScope.Global }),
      buildStatus({ id: 's2', template_id: 't2', order: 1, scope: StatusScope.RequestAccess }),
    ];
    const templates = [buildTemplate({ id: 't1', name: 'New' }), buildTemplate({ id: 't2', name: 'Pending' })];
    const { byScope } = convertStatusToDefinition(statuses, templates);

    const { definition } = pickMigrationScope('Case-Rfi', byScope, StatusScope.RequestAccess);

    expect(definition.states.map((s) => s.statusId)).toEqual(['t2']);
  });

  it('exposes diagnostics so the caller can gate publishing', () => {
    const statuses = [buildStatus({ id: 's1', template_id: 'missing', order: 1 })];
    const { byScope } = convertStatusToDefinition(statuses, []);

    const { diagnostics } = pickMigrationScope('Grouping', byScope);

    expect(diagnostics.map((d) => d.type)).toEqual(['MISSING_TEMPLATE']);
  });
});

describe('getPublishBlockingDiagnostics', () => {
  it('blocks on MISSING_TEMPLATE and NAME_CONFLICT only', () => {
    const diagnostics = [
      { type: 'MISSING_ORDER' as const, message: 'a' },
      { type: 'DUPLICATE_ORDER' as const, message: 'b' },
      { type: 'NAME_CONFLICT' as const, message: 'c' },
      { type: 'MISSING_TEMPLATE' as const, message: 'd' },
      { type: 'DUPLICATE_TEMPLATE' as const, message: 'e' },
      { type: 'EXISTING_WORKFLOW' as const, message: 'f' },
    ];
    expect(getPublishBlockingDiagnostics(diagnostics).map((d) => d.type)).toEqual(['NAME_CONFLICT', 'MISSING_TEMPLATE']);
  });
});

describe('convertRequestAccessGroup', () => {
  // Store order is shuffled on purpose: the conversion must rank by legacy order, not by store order.
  const requestAccessStatuses = [
    buildStatus({ id: 'ra-approved', template_id: 't-approved', type: 'Case-Rfi', scope: StatusScope.RequestAccess, order: 3 }),
    buildStatus({ id: 'ra-review', template_id: 't-review', type: 'Case-Rfi', scope: StatusScope.RequestAccess, order: 2 }),
    buildStatus({ id: 'ra-declined', template_id: 't-declined', type: 'Case-Rfi', scope: StatusScope.RequestAccess, order: 4 }),
    buildStatus({ id: 'ra-new', template_id: 't-new', type: 'Case-Rfi', scope: StatusScope.RequestAccess, order: 1 }),
  ];
  const requestAccessTemplates = [
    buildTemplate({ id: 't-new', name: 'New' }),
    buildTemplate({ id: 't-review', name: 'Under review' }),
    buildTemplate({ id: 't-approved', name: 'Approved' }),
    buildTemplate({ id: 't-declined', name: 'Declined' }),
  ];
  const convertSample = (approved = 't-approved', declined = 't-declined', statuses = requestAccessStatuses) => {
    const { byScope } = convertStatusToDefinition(statuses, requestAccessTemplates);
    return convertRequestAccessGroup(pickMigrationScope('Case-Rfi', byScope, StatusScope.RequestAccess), approved, declined);
  };
  const fromStates = (transition: WorkflowSerializedTransition) => (Array.isArray(transition.from) ? transition.from : [transition.from]);

  it('request-access conversion names transitions into outcome states Accept and Reject', () => {
    const { definition } = convertSample();

    const intoApproved = definition.transitions.filter((t) => t.to === 't-approved');
    const intoDeclined = definition.transitions.filter((t) => t.to === 't-declined');
    expect(intoApproved.map((t) => t.from)).toEqual(['t-new', 't-review']);
    expect(intoDeclined.map((t) => t.from)).toEqual(['t-new', 't-review']);
    expect(new Set(intoApproved.map((t) => t.event))).toEqual(new Set(['Accept']));
    expect(new Set(intoDeclined.map((t) => t.event))).toEqual(new Set(['Reject']));
  });

  it('drops every transition leaving Approved and Declined', () => {
    const { definition } = convertSample();

    expect(definition.transitions.filter((t) => fromStates(t).some((from) => ['t-approved', 't-declined'].includes(from)))).toEqual([]);
  });

  it('keeps the jump-anywhere transitions among the other request-access states', () => {
    const { definition } = convertSample();

    const others = definition.transitions.filter((t) => !['t-approved', 't-declined'].includes(t.to as string));
    expect(others).toEqual([
      { from: 't-review', to: 't-new', event: 'MOVE_TO_NEW' },
      { from: 't-new', to: 't-review', event: 'MOVE_TO_UNDER_REVIEW' },
    ]);
  });

  it('adds shareRequestedEntities with AUTHOR on Approved onEnter', () => {
    const { definition } = convertSample();

    const approved = definition.states.find((state) => state.statusId === 't-approved');
    expect(approved?.requestAccessOutcome).toBe('APPROVED');
    expect(approved?.onEnter).toEqual([{ type: 'shareRequestedEntities', params: { organizations: ['AUTHOR'] } }]);
    const declined = definition.states.find((state) => state.statusId === 't-declined');
    expect(declined?.requestAccessOutcome).toBe('DECLINED');
    expect(declined?.onEnter).toBeUndefined();
    expect(definition.states.filter((state) => state.requestAccessOutcome)).toHaveLength(2);
  });

  it('initial state is the lowest-order request-access status', () => {
    const { definition } = convertSample();

    expect(definition.initialState).toBe('t-new');
    expect(definition.states.map((state) => state.statusId)).toEqual(['t-new', 't-review', 't-approved', 't-declined']);
  });

  it('refuses when the lowest-order request-access status is an outcome state', () => {
    const statuses = requestAccessStatuses.map((status) => (status.id === 'ra-approved' ? { ...status, order: 0 } : status));

    expect(() => convertSample('t-approved', 't-declined', statuses)).toThrow('cannot be the initial state');
  });

  it('refuses when Approved and Declined share the same status template', () => {
    expect(() => convertSample('t-approved', 't-approved')).toThrow('must use different status templates');
  });

  it('refuses when an outcome template is not one of the request-access states', () => {
    expect(() => convertSample('t-approved', 't-unknown')).toThrow('not one of the request access statuses');
  });

  it('produces a definition that passes request access publish validation', async () => {
    const { definition } = convertSample();

    const errors = await validateWorkflowDefinitionData({} as any, {} as any, JSON.stringify(definition), 'Case-Rfi', undefined, StatusScope.RequestAccess);

    expect(errors).toEqual([]);
  });
});
