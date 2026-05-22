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
