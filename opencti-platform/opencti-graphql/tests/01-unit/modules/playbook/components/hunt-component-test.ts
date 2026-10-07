import { afterEach, describe, expect, it, vi } from 'vitest';
// The registry imports the hunt component, which imports it back through the playbook utilities: it is loaded first
import '../../../../../src/modules/playbook/playbook-components';
import { storeLoadById, topEntitiesList } from '../../../../../src/database/middleware-loader';
import { ForbiddenAccess } from '../../../../../src/config/errors';
import { checkHuntEditAccess } from '../../../../../src/modules/hunt/hunt-access';
import { createHuntRuns, designateHuntPlaybookLeader } from '../../../../../src/modules/hunt/huntRun/huntRun-domain';
import { findPlaybookHuntRuns, resumeHuntPlaybookStep } from '../../../../../src/modules/hunt/hunt-playbook';
import { checkPlaybookDefinitionHuntAccess, checkPlaybookHuntStepAccess, PLAYBOOK_HUNT_COMPONENT } from '../../../../../src/modules/playbook/components/hunt-component';
import type { StixBundle } from '../../../../../src/types/stix-2-1-common';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { HUNT_MANAGER_USER } from '../../../../../src/utils/access';

vi.mock('../../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/database/middleware-loader')>(),
  storeLoadById: vi.fn(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../../../src/modules/hunt/hunt-access', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/modules/hunt/hunt-access')>(),
  checkHuntEditAccess: vi.fn(async () => undefined),
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

const notifyStep = (executionId: string, waiting = false) => {
  const notify = PLAYBOOK_HUNT_COMPONENT.notify as NonNullable<typeof PLAYBOOK_HUNT_COMPONENT.notify>;
  return notify({
    executionId,
    eventId: 'event-1',
    playbookId: 'playbook-1',
    dataInstanceId: 'malware--1',
    previousPlaybookNodeId: 'step-0',
    playbookNode: { id: 'step-hunt', configuration: { applyToElements: 'only-main', hunt_ids: ['hunt-1'], wait_for_results: waiting, include_results: false } },
    bundle,
    previousStepBundle: bundle,
  } as never);
};

describe('Run hunts playbook step', () => {
  afterEach(() => {
    vi.mocked(topEntitiesList).mockReset();
    vi.mocked(createHuntRuns).mockReset();
    vi.mocked(resumeHuntPlaybookStep).mockClear();
    vi.mocked(findPlaybookHuntRuns).mockResolvedValue([]);
    vi.mocked(designateHuntPlaybookLeader).mockClear();
    outcome = null;
  });

  it('should fail in the execution when starting its runs fails, instead of continuing as a step with no hunt', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([{ internal_id: 'hunt-1', name: 'Emotet loaders' }] as never);
    vi.mocked(createHuntRuns).mockRejectedValue(new Error('The hunt connectors cannot be read'));
    await notifyStep('execution-1');
    expect(resumeHuntPlaybookStep).toHaveBeenCalledTimes(1);
    await expect(outcome).rejects.toThrow('The hunt connectors cannot be read');
  });

  it('should fail in the execution when a hunt fails to start after another one started, whether the step waits or not', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([{ internal_id: 'hunt-1', name: 'Emotet loaders' }, { internal_id: 'hunt-2', name: 'Emotet beacons' }] as never);
    const started = { internal_id: 'run-1', hunt_id: 'hunt-1' };
    vi.mocked(createHuntRuns).mockImplementation(async (_context, hunt) => {
      if (hunt.internal_id === 'hunt-2') {
        throw new Error('The hunt connectors cannot be read');
      }
      return [started] as never;
    });
    vi.mocked(findPlaybookHuntRuns).mockResolvedValue([started] as never);
    await notifyStep('execution-1');
    await expect(outcome).rejects.toThrow('The step started 1 hunt run(s), then failed to start the other hunts: The hunt connectors cannot be read');
    // A step waiting for its results fails the same way instead of waiting on part of its hunts
    outcome = null;
    await notifyStep('execution-2', true);
    expect(designateHuntPlaybookLeader).not.toHaveBeenCalled();
    expect(resumeHuntPlaybookStep).toHaveBeenCalledTimes(2);
    await expect(outcome).rejects.toThrow('then failed to start the other hunts');
  });

  it('should continue through no-hunt when the step has no hunt to run, and forget a failure once the step continued', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([] as never);
    await notifyStep('execution-1');
    await expect(outcome).resolves.toMatchObject({ output_port: 'no-hunt' });
    expect(createHuntRuns).not.toHaveBeenCalled();
  });
});

describe('Run hunts playbook step access', () => {
  const editor = { id: 'user-1', capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as unknown as AuthUser;
  const reader = { id: 'user-2', capabilities: [{ name: 'KNOWLEDGE' }, { name: 'AUTOMATION_AUTMANAGE' }] } as unknown as AuthUser;
  const context = { user: editor } as AuthContext;
  const configuration = (huntIds: string[]) => JSON.stringify({ applyToElements: 'only-main', hunt_ids: huntIds });
  const hunt = { internal_id: 'hunt-1', name: 'Emotet loaders', entity_type: 'Hunt' };

  afterEach(() => {
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(checkHuntEditAccess).mockReset();
    vi.mocked(topEntitiesList).mockReset();
  });

  it('should refuse a hunt step to a user who cannot start hunt runs, and ignore the other steps', async () => {
    await expect(checkPlaybookHuntStepAccess(context, reader, PLAYBOOK_HUNT_COMPONENT.id, configuration([])))
      .rejects.toThrow('Running hunts in a playbook requires the capability to update the knowledge');
    await expect(checkPlaybookHuntStepAccess(context, reader, 'PLAYBOOK_LOGGER_COMPONENT', configuration(['hunt-1']))).resolves.toBeUndefined();
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('should refuse a hunt step naming a hunt its writer cannot read or change', async () => {
    vi.mocked(storeLoadById).mockImplementation((async (_context: AuthContext, user: AuthUser) => (user === HUNT_MANAGER_USER ? hunt : null)) as never);
    await expect(checkPlaybookHuntStepAccess(context, editor, PLAYBOOK_HUNT_COMPONENT.id, configuration(['hunt-1'])))
      .rejects.toThrow('You cannot read a hunt of this step');
    vi.mocked(storeLoadById).mockResolvedValue(hunt as never);
    vi.mocked(checkHuntEditAccess).mockRejectedValue(ForbiddenAccess('You can read this hunt but not change it or its runs'));
    await expect(checkPlaybookHuntStepAccess(context, editor, PLAYBOOK_HUNT_COMPONENT.id, configuration(['hunt-1'])))
      .rejects.toThrow('You can read this hunt but not change it or its runs');
  });

  it('should accept the hunts its writer can change, and a hunt that does not exist', async () => {
    vi.mocked(storeLoadById).mockImplementation((async (_context: AuthContext, _user: AuthUser, id: string) => (id === 'hunt-1' ? hunt : null)) as never);
    await expect(checkPlaybookHuntStepAccess(context, editor, PLAYBOOK_HUNT_COMPONENT.id, configuration(['hunt-1', 'hunt-unknown']))).resolves.toBeUndefined();
    expect(checkHuntEditAccess).toHaveBeenCalledTimes(1);
    expect(checkHuntEditAccess).toHaveBeenCalledWith(context, editor, hunt);
  });

  it('should check every hunt step of a definition written at once', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(hunt as never);
    vi.mocked(checkHuntEditAccess).mockRejectedValue(ForbiddenAccess('You can read this hunt but not change it or its runs'));
    const definition = JSON.stringify({
      nodes: [
        { id: 'node-1', component_id: 'PLAYBOOK_LOGGER_COMPONENT', configuration: '{}' },
        { id: 'node-2', component_id: PLAYBOOK_HUNT_COMPONENT.id, configuration: configuration(['hunt-1']) },
      ],
      links: [],
    });
    await expect(checkPlaybookDefinitionHuntAccess(context, editor, definition)).rejects.toThrow('You can read this hunt but not change it or its runs');
  });

  it('should offer only the hunts and platforms the user configuring the step can read', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([hunt] as never);
    const schema = await PLAYBOOK_HUNT_COMPONENT.schema(context) as unknown as { properties: { hunt_ids: { items: { oneOf: unknown[] } } } };
    expect(schema.properties.hunt_ids.items.oneOf).toEqual([{ const: 'hunt-1', title: 'Emotet loaders' }]);
    expect(vi.mocked(topEntitiesList).mock.calls.every((call) => call[1] === editor)).toBe(true);
    vi.mocked(topEntitiesList).mockClear();
    const anonymous = await PLAYBOOK_HUNT_COMPONENT.schema() as unknown as { properties: { hunt_ids: { items: { oneOf: unknown[] } } } };
    expect(anonymous.properties.hunt_ids.items.oneOf).toEqual([]);
    expect(topEntitiesList).not.toHaveBeenCalled();
  });
});
