import { describe, it, expect, vi } from 'vitest';
import { WorkflowDefinition } from '../../../src/modules/workflow/workflow-definition';
import { WorkflowInstance } from '../../../src/modules/workflow/workflow-instance';

describe('Workflow Engine', () => {
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
