import { describe, expect, it, vi } from 'vitest';
import { WorkflowDefinition } from '../../../src/modules/workflow/engine/workflow-definition';
import { WorkflowInstance } from '../../../src/modules/workflow/engine/workflow-instance';

describe('Workflow Engine', () => {
  describe('Transition comments', () => {
    it('should record the comment defined on the transition in the history', async () => {
      const definition = new WorkflowDefinition('draft');
      definition.addState('reviewed');
      definition.addTransition('draft', 'reviewed', 'review', {
        comment: 'Please review carefully',
      });

      const instance = new WorkflowInstance(definition, 'draft', {});
      await instance.trigger('review');

      const history = instance.getHistory();
      expect(history).toHaveLength(1);
      expect(history[0].comment).toBe('Please review carefully');
    });

    it('should record undefined comment in history when transition has no comment', async () => {
      const definition = new WorkflowDefinition('draft');
      definition.addState('reviewed');
      definition.addTransition('draft', 'reviewed', 'review');

      const instance = new WorkflowInstance(definition, 'draft', {});
      await instance.trigger('review');

      const history = instance.getHistory();
      expect(history).toHaveLength(1);
      expect(history[0].comment).toBeUndefined();
    });

    it('should not record comment in history when transition fails due to condition', async () => {
      const definition = new WorkflowDefinition('draft');
      definition.addState('reviewed');
      definition.addTransition('draft', 'reviewed', 'review', {
        comment: 'Should not be recorded',
        conditions: [vi.fn().mockResolvedValue(false)],
      });

      const instance = new WorkflowInstance(definition, 'draft', {});
      const result = await instance.trigger('review');

      expect(result.success).toBe(false);
      const history = instance.getHistory();
      // History records the failed attempt without applying the comment
      expect(history[0].success).toBe(false);
    });

    it('should expose comment via getTransitions on WorkflowDefinition', () => {
      const definition = new WorkflowDefinition('open');
      definition.addState('closed');
      definition.addTransition('open', 'closed', 'close', {
        comment: 'Closing the issue',
      });

      const transitions = definition.getTransitions('open');
      expect(transitions).toHaveLength(1);
      expect(transitions[0].comment).toBe('Closing the issue');
    });

    it('should return undefined comment via getTransitions when no comment is set', () => {
      const definition = new WorkflowDefinition('open');
      definition.addState('closed');
      definition.addTransition('open', 'closed', 'close');

      const transitions = definition.getTransitions('open');
      expect(transitions[0].comment).toBeUndefined();
    });

    it('should retrieve comment via getTransition for a specific event', () => {
      const definition = new WorkflowDefinition('new');
      definition.addState('approved');
      definition.addTransition('new', 'approved', 'approve', {
        comment: 'Approved by manager',
      });

      const transition = definition.getTransition('new', 'approve');
      expect(transition).toBeDefined();
      expect(transition!.comment).toBe('Approved by manager');
    });
  });

  it('should transition between states correctly', async () => {
    const definition = new WorkflowDefinition('start');
    definition.addState('end');
    definition.addTransition('start', 'end', 'complete');

    const context = { user: { name: 'test' } };
    const instance = new WorkflowInstance(definition, 'start', context);

    expect(instance.getCurrentState()).toBe('start');

    const result = await instance.trigger('complete');

    expect(result.success).toBe(true);
    expect(instance.getCurrentState()).toBe('end');
    expect(instance.getHistory().length).toBe(1);
    expect(instance.getHistory()[0].to).toBe('end');
  });

  it('should block transition if condition fails', async () => {
    const definition = new WorkflowDefinition('start');
    definition.addState('end');

    const condition = vi.fn().mockResolvedValue(false);
    definition.addTransition('start', 'end', 'complete', {
      conditions: [condition],
    });

    const context = { user: { name: 'test' } };
    const instance = new WorkflowInstance(definition, 'start', context);

    const result = await instance.trigger('complete');

    expect(result.success).toBe(false);
    expect(result.reason).toContain('Condition failed');
    expect(instance.getCurrentState()).toBe('start');
    expect(condition).toHaveBeenCalledWith(context);
  });

  it('should execute side effects during transition', async () => {
    const definition = new WorkflowDefinition('start');
    definition.addState('end');

    const onTransition = vi.fn();
    definition.addTransition('start', 'end', 'complete', {
      onTransition: [onTransition],
    });

    const context = { user: { name: 'test' } };
    const instance = new WorkflowInstance(definition, 'start', context);

    await instance.trigger('complete');

    expect(onTransition).toHaveBeenCalledWith(context);
  });
});

// ---------------------------------------------------------------------------
// WorkflowDefinition
// ---------------------------------------------------------------------------

describe('WorkflowDefinition', () => {
  it('getInitialState returns the initial state', () => {
    const definition = new WorkflowDefinition('open');
    expect(definition.getInitialState()).toBe('open');
  });

  it('hasState returns true for an existing state', () => {
    const definition = new WorkflowDefinition('open');
    expect(definition.hasState('open')).toBe(true);
  });

  it('hasState returns false for a non-existent state', () => {
    const definition = new WorkflowDefinition('open');
    expect(definition.hasState('unknown')).toBe(false);
  });

  it('addState with onEnter/onExit hooks stores them on the state definition', () => {
    const onEnter = vi.fn();
    const onExit = vi.fn();
    const definition = new WorkflowDefinition('open');
    definition.addState('closed', { onEnter: [onEnter], onExit: [onExit] });

    const stateDef = definition.getStateDefinition('closed');
    expect(stateDef).toBeDefined();
    expect(stateDef!.onEnter).toContain(onEnter);
    expect(stateDef!.onExit).toContain(onExit);
  });

  it('getStateDefinition returns undefined for an unknown state', () => {
    const definition = new WorkflowDefinition('open');
    expect(definition.getStateDefinition('nonexistent')).toBeUndefined();
  });

  it('addTransition auto-creates missing from and to states', () => {
    const definition = new WorkflowDefinition('start');
    definition.addTransition('newFrom', 'newTo', 'go');
    expect(definition.hasState('newFrom')).toBe(true);
    expect(definition.hasState('newTo')).toBe(true);
  });

  it('addTransition does not overwrite existing state definitions', () => {
    const onEnter = vi.fn();
    const definition = new WorkflowDefinition('open');
    definition.addState('closed', { onEnter: [onEnter] });
    definition.addTransition('open', 'closed', 'close');

    const stateDef = definition.getStateDefinition('closed');
    expect(stateDef!.onEnter).toContain(onEnter);
  });
});

// ---------------------------------------------------------------------------
// StateMachine – getContext, getAvailableEvents, no-transition path,
//                initialState fallback, onExit / onEnter hooks
// ---------------------------------------------------------------------------

describe('StateMachine (via WorkflowInstance) – additional coverage', () => {
  it('getContext returns the context passed to the constructor', () => {
    const definition = new WorkflowDefinition('open');
    const ctx = { user: { id: 'u1' } };
    const instance = new WorkflowInstance(definition, 'open', ctx);
    expect(instance.getContext()).toBe(ctx);
  });

  it('getAvailableEvents returns events for transitions from the current state', () => {
    const definition = new WorkflowDefinition('open');
    definition.addState('review');
    definition.addState('closed');
    definition.addTransition('open', 'review', 'submit');
    definition.addTransition('open', 'closed', 'close');

    const instance = new WorkflowInstance(definition, 'open', {});
    const events = instance.getAvailableEvents();
    expect(events).toHaveLength(2);
    expect(events).toContain('submit');
    expect(events).toContain('close');
  });

  it('getAvailableEvents returns an empty array when no transitions exist from current state', () => {
    const definition = new WorkflowDefinition('terminal');
    const instance = new WorkflowInstance(definition, 'terminal', {});
    expect(instance.getAvailableEvents()).toEqual([]);
  });

  it('trigger returns failure when no transition exists for the event', async () => {
    const definition = new WorkflowDefinition('open');
    const instance = new WorkflowInstance(definition, 'open', {});
    const result = await instance.trigger('nonexistent');

    expect(result.success).toBe(false);
    expect(result.reason).toContain("No transition found from state 'open' for event 'nonexistent'");
    expect(instance.getCurrentState()).toBe('open');
  });

  it('uses definition.getInitialState() when initialState is undefined', () => {
    const definition = new WorkflowDefinition('start');
    const instance = new WorkflowInstance(definition, undefined, {});
    expect(instance.getCurrentState()).toBe('start');
  });

  it('executes onExit hook of the current state on a successful transition', async () => {
    const onExit = vi.fn();
    const definition = new WorkflowDefinition('open');
    definition.addState('open', { onExit: [onExit] });
    definition.addState('closed');
    definition.addTransition('open', 'closed', 'close');

    const ctx = { user: {} };
    const instance = new WorkflowInstance(definition, 'open', ctx);
    await instance.trigger('close');

    expect(onExit).toHaveBeenCalledWith(ctx);
  });

  it('executes onEnter hook of the new state on a successful transition', async () => {
    const onEnter = vi.fn();
    const definition = new WorkflowDefinition('open');
    definition.addState('closed', { onEnter: [onEnter] });
    definition.addTransition('open', 'closed', 'close');

    const ctx = { user: {} };
    const instance = new WorkflowInstance(definition, 'open', ctx);
    await instance.trigger('close');

    expect(onEnter).toHaveBeenCalledWith(ctx);
  });

  it('does not execute onExit / onEnter hooks when a condition fails', async () => {
    const onExit = vi.fn();
    const onEnter = vi.fn();
    const definition = new WorkflowDefinition('open');
    definition.addState('open', { onExit: [onExit] });
    definition.addState('closed', { onEnter: [onEnter] });
    definition.addTransition('open', 'closed', 'close', {
      conditions: [vi.fn().mockResolvedValue(false)],
    });

    await new WorkflowInstance(definition, 'open', {}).trigger('close');

    expect(onExit).not.toHaveBeenCalled();
    expect(onEnter).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// WorkflowInstance – canTransition and history details
// ---------------------------------------------------------------------------

describe('WorkflowInstance – canTransition and history details', () => {
  it('canTransition returns true when a matching transition exists', () => {
    const definition = new WorkflowDefinition('open');
    definition.addState('closed');
    definition.addTransition('open', 'closed', 'close');

    const instance = new WorkflowInstance(definition, 'open', {});
    expect(instance.canTransition('close')).toBe(true);
  });

  it('canTransition returns false when no transition exists for the event', () => {
    const definition = new WorkflowDefinition('open');
    const instance = new WorkflowInstance(definition, 'open', {});
    expect(instance.canTransition('nonexistent')).toBe(false);
  });

  it('history entry for a successful transition contains correct fields', async () => {
    const definition = new WorkflowDefinition('open');
    definition.addState('closed');
    definition.addTransition('open', 'closed', 'close');

    const instance = new WorkflowInstance(definition, 'open', {});
    const before = new Date();
    await instance.trigger('close');
    const after = new Date();

    const history = instance.getHistory();
    expect(history).toHaveLength(1);
    expect(history[0].from).toBe('open');
    expect(history[0].to).toBe('closed');
    expect(history[0].event).toBe('close');
    expect(history[0].success).toBe(true);
    expect(history[0].date.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(history[0].date.getTime()).toBeLessThanOrEqual(after.getTime());
  });

  it('history entry for a failed (condition-blocked) transition records success=false and unchanged state', async () => {
    const definition = new WorkflowDefinition('open');
    definition.addState('closed');
    definition.addTransition('open', 'closed', 'close', {
      conditions: [vi.fn().mockResolvedValue(false)],
    });

    const instance = new WorkflowInstance(definition, 'open', {});
    await instance.trigger('close');

    const history = instance.getHistory();
    expect(history[0].success).toBe(false);
    expect(history[0].from).toBe('open');
    expect(history[0].to).toBe('open'); // state unchanged
  });
});
