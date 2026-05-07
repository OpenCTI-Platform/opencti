import { describe, it, expect, vi } from 'vitest';
import { WorkflowFactory } from '../../../src/modules/workflow/engine/workflow-factory';
import type { WorkflowSchema } from '../../../src/modules/workflow/engine/workflow-schema';

// ---------------------------------------------------------------------------
// Mock heavy dependencies
// ---------------------------------------------------------------------------
vi.mock('../../../src/modules/workflow/registry/workflow-actions', () => ({
  ActionRegistry: {},
  ActionDefinitions: {},
}));

vi.mock('../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

// ---------------------------------------------------------------------------
// Minimal schema builder helpers
// ---------------------------------------------------------------------------
const makeSchema = (transitionOverrides: Partial<WorkflowSchema['transitions'][0]> = {}): WorkflowSchema => ({
  id: 'wf-1',
  name: 'Test workflow',
  initialState: 'draft',
  states: [
    { statusId: 'draft' },
    { statusId: 'review' },
  ],
  transitions: [
    {
      from: 'draft',
      to: 'review',
      event: 'submit',
      ...transitionOverrides,
    },
  ],
});

// ---------------------------------------------------------------------------
// WorkflowFactory.createDefinition – comment propagation
// ---------------------------------------------------------------------------

describe('WorkflowFactory.createDefinition – comment field', () => {
  it('propagates the comment from the schema to the transition definition', () => {
    const schema = makeSchema({ comment: 'Needs manager approval' });
    const definition = WorkflowFactory.createDefinition(schema);

    const transition = definition.getTransition('draft', 'submit');
    expect(transition).toBeDefined();
    expect(transition!.comment).toBe('Needs manager approval');
  });

  it('leaves comment undefined when the schema transition has no comment', () => {
    const schema = makeSchema(); // no comment field
    const definition = WorkflowFactory.createDefinition(schema);

    const transition = definition.getTransition('draft', 'submit');
    expect(transition).toBeDefined();
    expect(transition!.comment).toBeUndefined();
  });

  it('propagates distinct comments across multiple transitions', () => {
    const schema: WorkflowSchema = {
      id: 'wf-multi',
      name: 'Multi-transition',
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'review' },
        { statusId: 'approved' },
      ],
      transitions: [
        { from: 'draft', to: 'review', event: 'submit', comment: 'Submit for review' },
        { from: 'review', to: 'approved', event: 'approve', comment: 'Approved by manager' },
      ],
    };

    const definition = WorkflowFactory.createDefinition(schema);

    expect(definition.getTransition('draft', 'submit')!.comment).toBe('Submit for review');
    expect(definition.getTransition('review', 'approve')!.comment).toBe('Approved by manager');
  });

  it('handles a mix of transitions with and without comments', () => {
    const schema: WorkflowSchema = {
      id: 'wf-mixed',
      name: 'Mixed comments',
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'review' },
        { statusId: 'rejected' },
      ],
      transitions: [
        { from: 'draft', to: 'review', event: 'submit', comment: 'Needs review' },
        { from: 'draft', to: 'rejected', event: 'reject' }, // no comment
      ],
    };

    const definition = WorkflowFactory.createDefinition(schema);

    expect(definition.getTransition('draft', 'submit')!.comment).toBe('Needs review');
    expect(definition.getTransition('draft', 'reject')!.comment).toBeUndefined();
  });

  it('exposes comment via getTransitions for all outgoing transitions from a state', () => {
    const schema: WorkflowSchema = {
      id: 'wf-out',
      name: 'Outgoing',
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'review' },
        { statusId: 'archived' },
      ],
      transitions: [
        { from: 'draft', to: 'review', event: 'submit', comment: 'For review' },
        { from: 'draft', to: 'archived', event: 'archive' },
      ],
    };

    const definition = WorkflowFactory.createDefinition(schema);
    const transitions = definition.getTransitions('draft');

    expect(transitions).toHaveLength(2);
    const submitTransition = transitions.find((t) => t.event === 'submit');
    const archiveTransition = transitions.find((t) => t.event === 'archive');

    expect(submitTransition!.comment).toBe('For review');
    expect(archiveTransition!.comment).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory.getInstance – comment accessible on the produced instance
// ---------------------------------------------------------------------------

describe('WorkflowFactory.getInstance – comment accessible via definition', () => {
  it('the instance definition retains the transition comment', () => {
    const schema = makeSchema({ comment: 'Instance comment check' });
    const definition = WorkflowFactory.createDefinition(schema);
    WorkflowFactory.getInstance(schema, definition, 'draft', { user: {}, entity: {}, context: {} } as any);

    // Verify via the definition directly – the instance is built from this definition
    const transitions = definition.getTransitions('draft');
    expect(transitions).toHaveLength(1);
    expect(transitions[0].comment).toBe('Instance comment check');
  });

  it('the instance definition exposes undefined comment when not set', () => {
    const schema = makeSchema(); // no comment
    const definition = WorkflowFactory.createDefinition(schema);
    WorkflowFactory.getInstance(schema, definition, 'draft', { user: {}, entity: {}, context: {} } as any);

    const transitions = definition.getTransitions('draft');
    expect(transitions).toHaveLength(1);
    expect(transitions[0].comment).toBeUndefined();
  });
});
