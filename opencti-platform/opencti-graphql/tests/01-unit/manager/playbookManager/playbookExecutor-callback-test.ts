import { beforeEach, describe, expect, it, vi } from 'vitest';
import { redisPlaybookUpdate } from '../../../../src/database/redis';
import { playbookExecutor } from '../../../../src/manager/playbookManager/playbookExecutor';
import { createContinuationScheduler } from '../../../../src/manager/playbookManager/playbookContinuationScheduler';
import { PLAYBOOK_COMPONENTS } from '../../../../src/modules/playbook/playbook-components';
import type { ComponentDefinition, PlaybookComponent } from '../../../../src/modules/playbook/playbook-types';
import type { StixBundle } from '../../../../src/types/stix-2-1-common';

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  redisPlaybookUpdate: vi.fn(async () => {}),
}));

vi.mock('../../../../src/manager/telemetryManager', () => ({
  addPlaybookExecutionCount: vi.fn(),
}));

const CONNECTOR_COMPONENT_ID = 'TEST_CONNECTOR_COMPONENT';
const SLOW_COMPONENT_ID = 'TEST_SLOW_COMPONENT';
const FAILING_COMPONENT_ID = 'TEST_FAILING_COMPONENT';
const SLOW_STEP_MS = 1500;

const bundle = (id: string): StixBundle => ({ id: `bundle--${id}`, spec_version: '2.1', type: 'bundle', objects: [] } as unknown as StixBundle);

const baseComponent = (id: string, isInternal: boolean): PlaybookComponent<object> => ({
  id,
  name: id,
  description: id,
  icon: 'test',
  category: 'transform_and_enrich',
  is_entry_point: false,
  is_internal: isInternal,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: undefined,
  schema: async () => undefined,
  executor: async ({ bundle: b }) => ({ output_port: 'out', bundle: b }),
});

const slowExecutor = vi.fn(async ({ bundle: b }: { bundle: StixBundle }) => {
  await new Promise((resolve) => {
    setTimeout(resolve, SLOW_STEP_MS);
  });
  return { output_port: undefined, bundle: b };
});

const failingExecutor = vi.fn(async () => {
  throw new Error('downstream failure');
});

const definition = (downstreamComponentId: string): ComponentDefinition => ({
  nodes: [
    { id: 'previous-node', name: 'Previous', component_id: 'TEST_PREVIOUS', configuration: '{}' },
    { id: 'connector-node', name: 'Connector step', component_id: CONNECTOR_COMPONENT_ID, configuration: '{}' },
    { id: 'downstream-node', name: 'Downstream step', component_id: downstreamComponentId, configuration: '{}' },
  ],
  links: [{ from: { id: 'connector-node', port: 'out' }, to: { id: 'downstream-node' } }],
} as unknown as ComponentDefinition);

const run = (downstreamComponentId: string, external: boolean) => {
  const def = definition(downstreamComponentId);
  const connector = PLAYBOOK_COMPONENTS[CONNECTOR_COMPONENT_ID];
  return playbookExecutor({
    eventId: 'event-id',
    executionId: 'execution-id',
    playbookId: 'playbook-id',
    dataInstanceId: 'data-instance-id',
    definition: def,
    previousStep: { component: connector, instance: def.nodes[0] },
    nextStep: { component: connector, instance: def.nodes[1] },
    previousStepBundle: bundle('previous'),
    bundle: bundle('connector-output'),
    externalCallback: external ? { externalStartDate: new Date() } : undefined,
  });
};

const observedSteps = () => vi.mocked(redisPlaybookUpdate).mock.calls.map(([envelop]) => ({
  step: envelop.last_execution_step,
  status: (envelop as Record<string, any>)[`step_${envelop.last_execution_step}`].status,
}));

describe('playbookExecutor on an external callback', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Connector step: not internal, it answers through playbookStepExecution
    PLAYBOOK_COMPONENTS[CONNECTOR_COMPONENT_ID] = { ...baseComponent(CONNECTOR_COMPONENT_ID, false), notify: async () => {} };
    PLAYBOOK_COMPONENTS[SLOW_COMPONENT_ID] = { ...baseComponent(SLOW_COMPONENT_ID, true), executor: slowExecutor };
    PLAYBOOK_COMPONENTS[FAILING_COMPONENT_ID] = { ...baseComponent(FAILING_COMPONENT_ID, true), executor: failingExecutor };
  });

  it('acknowledges the callback before a slow downstream step ends, and still runs and records it', async () => {
    const started = Date.now();
    await run(SLOW_COMPONENT_ID, true);
    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(1000);
    // The connector step is registered before the answer
    expect(observedSteps()).toEqual([{ step: 'connector-node', status: 'success' }]);
    // The downstream step runs in the background and its observation is recorded
    await vi.waitFor(() => {
      expect(observedSteps()).toEqual([
        { step: 'connector-node', status: 'success' },
        { step: 'downstream-node', status: 'success' },
      ]);
    }, { timeout: SLOW_STEP_MS * 3, interval: 50 });
    expect(slowExecutor).toHaveBeenCalledTimes(1);
  });

  it('registers an error of a downstream step as an error observation, never an unhandled rejection', async () => {
    await run(FAILING_COMPONENT_ID, true);
    await vi.waitFor(() => {
      expect(observedSteps()).toEqual([
        { step: 'connector-node', status: 'success' },
        { step: 'downstream-node', status: 'error' },
      ]);
    }, { timeout: 2000, interval: 20 });
    expect(failingExecutor).toHaveBeenCalledTimes(1);
  });

  it('keeps awaiting the whole chain on an internal path (no external callback)', async () => {
    PLAYBOOK_COMPONENTS[CONNECTOR_COMPONENT_ID] = baseComponent(CONNECTOR_COMPONENT_ID, true);
    await run(SLOW_COMPONENT_ID, false);
    // Both steps are recorded when the call returns
    expect(observedSteps()).toEqual([
      { step: 'connector-node', status: 'success' },
      { step: 'downstream-node', status: 'success' },
    ]);
  });
});

type Gate = { release: () => void; started: boolean; done: boolean };

// A task that runs until its gate is released, so a test drives slow chains by hand.
const gatedTask = (gates: Gate[]) => () => new Promise<void>((resolve) => {
  const gate: Gate = { started: true, done: false, release: () => {} };
  gate.release = () => {
    gate.done = true;
    resolve();
  };
  gates.push(gate);
});

describe('createContinuationScheduler', () => {
  it('never runs more tasks at once than its limit and never makes the caller wait for a slot', async () => {
    const scheduler = createContinuationScheduler({ maxConcurrency: 2, maxConcurrencyPerPlaybook: 2 });
    const gates: Gate[] = [];
    await scheduler.schedule(gatedTask(gates), { playbookId: 'a' });
    await scheduler.schedule(gatedTask(gates), { playbookId: 'a' });
    // Third call resolves at once, the task is queued
    const started = Date.now();
    await scheduler.schedule(gatedTask(gates), { playbookId: 'a' });
    expect(Date.now() - started).toBeLessThan(50);
    expect(scheduler.running()).toBe(2);
    expect(scheduler.waiting()).toBe(1);
    expect(gates.length).toBe(2);
    gates[0].release();
    await vi.waitFor(() => expect(gates.length).toBe(3));
    expect(scheduler.running()).toBe(2);
    expect(scheduler.waiting()).toBe(0);
    gates.forEach((gate) => gate.release());
    await vi.waitFor(() => expect(scheduler.running()).toBe(0));
  });

  it('runs the callback of a fast playbook at once while slow chains of other playbooks hold slots', async () => {
    // The issue scenario: 10 slots, slow AI chains of several playbooks, then one fast callback of another playbook
    const scheduler = createContinuationScheduler({ maxConcurrency: 10, maxConcurrencyPerPlaybook: 3 });
    const slow: Gate[] = [];
    // schedule() runs synchronously up to its return, so the calls are queued in order
    await Promise.all(Array.from({ length: 12 }, (_, index) => scheduler.schedule(gatedTask(slow), { playbookId: `slow-${index % 3}` })));
    // Per-playbook cap: 3 slow playbooks x 3 slots = 9 running, 3 queued, 1 slot left for anybody else
    expect(scheduler.running()).toBe(9);
    expect(scheduler.waiting()).toBe(3);
    expect(scheduler.runningFor('slow-0')).toBe(3);
    let fastDone = false;
    const started = Date.now();
    await scheduler.schedule(async () => {
      fastDone = true;
    }, { playbookId: 'fast' });
    expect(Date.now() - started).toBeLessThan(50);
    await vi.waitFor(() => expect(fastDone).toBe(true));
    // No slow chain ended: the fast one did not wait for them
    expect(slow.every((gate) => !gate.done)).toBe(true);
    slow.forEach((gate) => gate.release());
    await vi.waitFor(() => expect(slow.length).toBe(12));
    slow.forEach((gate) => gate.release());
    await vi.waitFor(() => expect(scheduler.running()).toBe(0));
    expect(scheduler.waiting()).toBe(0);
  });

  it('respects the per-playbook cap even when global slots are free', async () => {
    const scheduler = createContinuationScheduler({ maxConcurrency: 10, maxConcurrencyPerPlaybook: 2 });
    const gates: Gate[] = [];
    await Promise.all(Array.from({ length: 5 }, () => scheduler.schedule(gatedTask(gates), { playbookId: 'slow' })));
    expect(scheduler.runningFor('slow')).toBe(2);
    expect(scheduler.waiting()).toBe(3);
    gates[0].release();
    await vi.waitFor(() => expect(gates.length).toBe(3));
    expect(scheduler.runningFor('slow')).toBe(2);
    await vi.waitFor(() => {
      gates.forEach((gate) => gate.release());
      expect(scheduler.running()).toBe(0);
    });
    expect(gates.length).toBe(5);
  });

  it('serves queued playbooks round-robin, so one backlog does not hold another back', async () => {
    const scheduler = createContinuationScheduler({ maxConcurrency: 1, maxConcurrencyPerPlaybook: 1 });
    const order: string[] = [];
    const gates: Gate[] = [];
    await scheduler.schedule(gatedTask(gates), { playbookId: 'a' });
    await Promise.all(Array.from({ length: 3 }, (_, index) => scheduler.schedule(async () => {
      order.push(`a${index}`);
    }, { playbookId: 'a' })));
    await scheduler.schedule(async () => {
      order.push('b0');
    }, { playbookId: 'b' });
    gates[0].release();
    await vi.waitFor(() => expect(order.length).toBe(4));
    expect(order.indexOf('b0')).toBeLessThan(2);
  });

  it('bounds the backlog: a callback past the limit is refused and never runs later', async () => {
    const scheduler = createContinuationScheduler({ maxConcurrency: 1, maxConcurrencyPerPlaybook: 1, maxWaiting: 2 });
    const gates: Gate[] = [];
    scheduler.assertAccepting();
    await scheduler.schedule(gatedTask(gates), { playbookId: 'a' });
    scheduler.assertAccepting();
    await scheduler.schedule(gatedTask(gates), { playbookId: 'a' });
    scheduler.assertAccepting();
    await scheduler.schedule(gatedTask(gates), { playbookId: 'b' });
    expect(scheduler.waiting()).toBe(2);
    expect(() => scheduler.assertAccepting({ playbookId: 'c' })).toThrow('Playbook continuation backlog is full');
    expect(scheduler.waiting()).toBe(2);
    await vi.waitFor(() => {
      gates.forEach((gate) => gate.release());
      expect(scheduler.running()).toBe(0);
    });
    // Only the three accepted tasks ever ran
    expect(gates.length).toBe(3);
    scheduler.assertAccepting();
  });

  it('logs a task error and frees its slot', async () => {
    const scheduler = createContinuationScheduler({ maxConcurrency: 1 });
    await scheduler.schedule(async () => {
      throw new Error('boom');
    });
    await vi.waitFor(() => expect(scheduler.running()).toBe(0));
    let ran = false;
    await scheduler.schedule(async () => {
      ran = true;
    });
    await vi.waitFor(() => expect(ran).toBe(true));
  });
});
