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

describe('createContinuationScheduler', () => {
  it('never runs more tasks at once than its limit and makes the caller wait for a free slot only', async () => {
    const scheduler = createContinuationScheduler(2);
    let concurrent = 0;
    let maxConcurrent = 0;
    const releases: Array<() => void> = [];
    const task = () => new Promise<void>((resolve) => {
      concurrent += 1;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      releases.push(() => {
        concurrent -= 1;
        resolve();
      });
    });
    await scheduler.schedule(task);
    await scheduler.schedule(task);
    expect(scheduler.running()).toBe(2);
    // Third caller waits for a slot
    let thirdAccepted = false;
    const third = scheduler.schedule(task).then(() => {
      thirdAccepted = true;
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 20);
    });
    expect(thirdAccepted).toBe(false);
    expect(scheduler.waiting()).toBe(1);
    releases.shift()?.();
    await third;
    expect(thirdAccepted).toBe(true);
    expect(maxConcurrent).toBe(2);
    releases.splice(0).forEach((release) => release());
    await vi.waitFor(() => expect(scheduler.running()).toBe(0));
  });

  it('logs a task error and frees its slot', async () => {
    const scheduler = createContinuationScheduler(1);
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
