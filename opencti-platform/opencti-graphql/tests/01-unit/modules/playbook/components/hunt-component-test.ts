import { afterEach, describe, expect, it, vi } from 'vitest';
// The registry imports the hunt component, which imports it back through the playbook utilities: it is loaded first
import '../../../../../src/modules/playbook/playbook-components';
import { topEntitiesList } from '../../../../../src/database/middleware-loader';
import { createHuntRuns } from '../../../../../src/modules/hunt/huntRun/huntRun-domain';
import { resumeHuntPlaybookStep } from '../../../../../src/modules/hunt/hunt-playbook';
import { PLAYBOOK_HUNT_COMPONENT } from '../../../../../src/modules/playbook/components/hunt-component';
import type { StixBundle } from '../../../../../src/types/stix-2-1-common';

vi.mock('../../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/database/middleware-loader')>(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/database/engine')>(),
  elCount: vi.fn(async () => 0),
}));

vi.mock('../../../../../src/modules/hunt/hunt-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/modules/hunt/hunt-lock')>(),
  withHuntLock: vi.fn(async (_key, action) => action()),
}));

vi.mock('../../../../../src/modules/hunt/huntRun/huntRun-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/modules/hunt/huntRun/huntRun-domain')>(),
  createHuntRuns: vi.fn(),
  designateHuntPlaybookLeader: vi.fn(),
}));

// The playbook manager runs the executor of the step as soon as the step continues, in the same process
let outcome: Promise<unknown> | null = null;
vi.mock('../../../../../src/modules/hunt/hunt-playbook', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/modules/hunt/hunt-playbook')>(),
  findPlaybookHuntRuns: vi.fn(async () => []),
  resumeHuntPlaybookStep: vi.fn(async (_context, playbookContext) => {
    const executor = PLAYBOOK_HUNT_COMPONENT.executor as NonNullable<typeof PLAYBOOK_HUNT_COMPONENT.executor>;
    outcome = executor({
      executionId: playbookContext.execution_id,
      dataInstanceId: playbookContext.data_instance_id,
      playbookNode: { id: playbookContext.step_id },
      bundle: JSON.parse(playbookContext.bundle),
    } as never);
    await outcome.catch(() => undefined);
  }),
}));

const bundle = { id: 'bundle--1', type: 'bundle', objects: [{ id: 'malware--1', type: 'malware', name: 'Emotet' }] } as unknown as StixBundle;

const notifyStep = (executionId: string) => {
  const notify = PLAYBOOK_HUNT_COMPONENT.notify as NonNullable<typeof PLAYBOOK_HUNT_COMPONENT.notify>;
  return notify({
    executionId,
    eventId: 'event-1',
    playbookId: 'playbook-1',
    dataInstanceId: 'malware--1',
    previousPlaybookNodeId: 'step-0',
    playbookNode: { id: 'step-hunt', configuration: { applyToElements: 'only-main', hunt_ids: ['hunt-1'], wait_for_results: false, include_results: false } },
    bundle,
    previousStepBundle: bundle,
  } as never);
};

describe('Run hunts playbook step', () => {
  afterEach(() => {
    vi.mocked(topEntitiesList).mockReset();
    vi.mocked(createHuntRuns).mockReset();
    vi.mocked(resumeHuntPlaybookStep).mockClear();
    outcome = null;
  });

  it('should fail in the execution when starting its runs fails, instead of continuing as a step with no hunt', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([{ internal_id: 'hunt-1', name: 'Emotet loaders' }] as never);
    vi.mocked(createHuntRuns).mockRejectedValue(new Error('The hunt connectors cannot be read'));
    await notifyStep('execution-1');
    expect(resumeHuntPlaybookStep).toHaveBeenCalledTimes(1);
    await expect(outcome).rejects.toThrow('The hunt connectors cannot be read');
  });

  it('should continue through no-hunt when the step has no hunt to run, and forget a failure once the step continued', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([] as never);
    await notifyStep('execution-1');
    await expect(outcome).resolves.toMatchObject({ output_port: 'no-hunt' });
    expect(createHuntRuns).not.toHaveBeenCalled();
  });
});
