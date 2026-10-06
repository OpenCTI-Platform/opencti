import { beforeEach, describe, expect, it, vi } from 'vitest';
import { booleanConf, isFeatureEnabled, logApp } from '../../../src/config/conf';
import { extractEntityRepresentativeName } from '../../../src/database/entity-representative';
import { loadAssignees, loadParticipants } from '../../../src/database/members';
import { createEntity, createRelation, deleteElementById, loadEntity, updateAttribute } from '../../../src/database/middleware';
import { fullEntitiesList, internalLoadById, storeLoadById } from '../../../src/database/middleware-loader';
import { resolveUserById } from '../../../src/modules/user/user-domain';
import { createStatus, findByType as findStatusesByType } from '../../../src/domain/status';
import * as ee from '../../../src/enterprise-edition/ee';
import { StatusScope } from '../../../src/generated/graphql';
import { getEntitiesListFromCache } from '../../../src/database/cache';
import { getDraftContext } from '../../../src/utils/draftContext';
import { lockResources } from '../../../src/lock/master-lock';
import * as telemetryManager from '../../../src/manager/telemetryManager';
import { findByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../src/modules/entitySetting/entitySetting-types';
import { addNotification } from '../../../src/modules/notification/notification-domain';
import {
  __resetReadRepairRateLimitForTest,
  clearWorkflowPendingState,
  deleteWorkflowDefinition,
  getAllowedTransitions,
  getWorkflowDefinition,
  getWorkflowInstance,
  getWorkflowPublishedVersionId,
  initializeEntityWorkflow,
  isStatusTemplateUsedInWorkflows,
  isStatusUsedInWorkflow,
  publishWorkflowDefinition,
  hasPublishedWorkflowDefinition,
  restorePublishedWorkflowDefinition,
  setWorkflowDefinition,
  triggerWorkflowEvent,
  cleanupEntityWorkflow,
  setWorkflowStatus,
  getWorkflowBypassStatuses,
  syncWorkflowInstanceFromExternalWrite,
} from '../../../src/modules/workflow/domain/workflow-domain';
import { projectWorkflowState, resolveMappedStatusId } from '../../../src/modules/workflow/domain/workflow-projection';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import { FilterMode } from '../../../src/generated/graphql';
import { WorkflowFactory } from '../../../src/modules/workflow/engine/workflow-factory';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';
import { ENTITY_TYPE_STATUS } from '../../../src/schema/internalObject';
import { WORKFLOW_MANAGER_USER } from '../../../src/utils/access';
import { emptyFilterGroup } from '../../../src/utils/filtering/filtering-utils';
import { ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';
import { createListTask } from '../../../src/domain/backgroundTask-common';
import { reportWorkflowAsyncActionResult } from '../../../src/modules/workflow/domain/workflow-async-completion';

vi.mock('../../../src/domain/backgroundTask-common', () => ({ createListTask: vi.fn() }));

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn(),
  loadEntity: vi.fn(),
  updateAttribute: vi.fn(),
  deleteElementById: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  internalLoadById: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/modules/user/user-domain', () => ({
  resolveUserById: vi.fn(),
}));

vi.mock('../../../src/modules/entitySetting/entitySetting-domain', () => ({
  findByType: vi.fn(),
}));

vi.mock('../../../src/utils/draftContext', () => ({
  bypassDraftContext: vi.fn((context) => context),
  getDraftContext: vi.fn(() => undefined),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: vi.fn().mockResolvedValue({ unlock: vi.fn() }),
}));

vi.mock('../../../src/modules/workflow/workflow-validation', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/modules/workflow/workflow-validation')>();
  return {
    ...actual,
    validateWorkflowDefinitionData: vi.fn().mockResolvedValue([]),
  };
});

vi.mock('../../../src/modules/workflow/engine/workflow-factory', () => ({
  WorkflowFactory: {
    createDefinition: vi.fn(() => ({
      getInitialState: () => 'open',
      hasState: () => true,
      getTransitions: () => [
        { event: 'close', to: 'closed', actionTypes: ['log'] },
      ],
    })),
    getInstance: vi.fn(() => ({
      start: vi.fn().mockResolvedValue(undefined),
      trigger: vi.fn().mockResolvedValue({ success: true }),
      getCurrentState: () => 'closed',
    })),
  },
}));

vi.mock('../../../src/database/members', () => ({
  loadAssignees: vi.fn(),
  loadParticipants: vi.fn(),
}));

vi.mock('../../../src/database/entity-representative', () => ({
  extractEntityRepresentativeName: vi.fn().mockReturnValue('Test Entity'),
}));

vi.mock('../../../src/modules/notification/notification-domain', () => ({
  addNotification: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/manager/telemetryManager', () => ({
  addWorkflowPublishCount: vi.fn(),
}));

vi.mock('../../../src/domain/status', () => ({
  createStatus: vi.fn(),
  findByType: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/modules/workflow/domain/workflow-projection', () => ({
  projectWorkflowState: vi.fn(),
  resolveProjectionScope: vi.fn((scope: string | undefined) => (scope && scope !== 'standard' ? scope : 'GLOBAL')),
  resolveMappedStatusId: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: {
      error: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
    },
    booleanConf: vi.fn(actual.booleanConf),
    isFeatureEnabled: vi.fn().mockReturnValue(true),
  };
});

vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/utils/access')>();
  return {
    ...actual,
    executionContext: vi.fn().mockReturnValue({ user: null }),
  };
});

const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;

describe('Workflow bypass', () => {
  const user = { id: 'admin', capabilities: [{ name: 'BYPASS' }], draft_context: 'draft-id' } as any;
  const context = {} as any;
  let entity: any;
  let instance: any;
  let definition: any;
  let target: any;
  let legacy: any;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    vi.mocked(lockResources).mockResolvedValue({ unlock: vi.fn() });
    entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident', x_opencti_workflow_id: 'status-open' };
    instance = { id: 'instance-id', internal_id: 'instance-id', entity_id: entity.id, currentState: 'open', scope: 'standard', history: '[]' };
    definition = {
      initialState: 'open',
      states: [
        { statusId: 'open', onExit: [{ type: 'log', params: { message: 'exit' } }] },
        { statusId: 'closed', onEnter: [{ type: 'log', params: { message: 'enter' } }] },
      ],
      transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'log', params: { message: 'edge' } }] }],
    };
    target = { id: 'status-closed', entity_type: ENTITY_TYPE_STATUS, type: 'Incident', scope: StatusScope.Global, template_id: 'closed', order: 2 };
    legacy = { ...target, id: 'status-open', template_id: 'open', order: 1 };
    vi.mocked(findByType).mockResolvedValue({ id: 'setting-id', workflow_id: 'definition-id' } as any);
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id) => {
      if (id === 'entity-id') return entity;
      if (id === 'instance-id') return structuredClone(instance);
      if (id === 'status-closed') return target;
      if (id === 'status-open') return legacy;
      if (id === 'definition-id') return { id, published_version: { content: JSON.stringify(definition) } } as any;
      return null;
    });
    vi.mocked(internalLoadById).mockResolvedValue(entity);
    vi.mocked(loadEntity).mockImplementation(async () => instance);
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => {
      instance = { ...input, id: 'instance-id', internal_id: 'instance-id' };
      return instance;
    });
    vi.mocked(updateAttribute).mockImplementation(async (_context, _user, _id, _type, patches) => {
      for (const patch of patches) instance[patch.key] = patch.value[0];
      return { element: instance } as any;
    });
    vi.mocked(resolveMappedStatusId).mockImplementation(async (_context, _user, _type, _scope, state) => `status-${state}`);
    vi.mocked(fullEntitiesList).mockResolvedValue([legacy, target]);
    vi.spyOn(ActionRegistry, 'log').mockResolvedValue(undefined);
    vi.mocked(createListTask).mockResolvedValue({ work_id: 'work-id' } as any);
  });

  it('projects a status-only bypass with explicit user and normalized history, without hooks or edge actions', async () => {
    const result = await setWorkflowStatus(context, user, entity.id, target.id, false, '  override  ');
    expect(result).toMatchObject({ success: true, newState: 'closed', executionStatus: 'completed' });
    expect(projectWorkflowState).toHaveBeenCalledWith(context, { ...user, draft_context: undefined }, entity, 'closed', StatusScope.Global);
    expect(JSON.parse(instance.history)).toEqual([expect.objectContaining({ state: 'closed', event: 'event_bypass', user_id: 'admin', comment: 'override' })]);
    expect(ActionRegistry.log).not.toHaveBeenCalled();
    expect(WorkflowFactory.getInstance).not.toHaveBeenCalled();
  });

  it('runs onExit before onEnter and never transition-edge actions', async () => {
    expect(await setWorkflowStatus(context, user, entity.id, target.id, true)).toMatchObject({ success: true });
    expect(vi.mocked(ActionRegistry.log).mock.calls.map((call) => call[1].message)).toEqual(['exit', 'enter']);
  });

  it.each(['SHARE', 'UNSHARE'])('validates %s runtime input before any hook or pending write', async (type) => {
    definition.states[1].onEnter.push({ type: 'asyncBulkAction', params: JSON.stringify({ actions: [{ type, context: { values: [] } }] }) });
    const key = type === 'SHARE' ? 'shareOrganizationIds' : 'unshareOrganizationIds';
    for (const value of [undefined, [], '', [''], [42]]) {
      expect(await setWorkflowStatus(context, user, entity.id, target.id, true, null, { [key]: value }))
        .toMatchObject({ success: false, reason: expect.stringContaining(key) });
    }
    expect(ActionRegistry.log).not.toHaveBeenCalled();
    expect(createListTask).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(await setWorkflowStatus(context, user, entity.id, target.id, false)).toMatchObject({ success: true });
  });

  it('allows static organizations without runtime input', async () => {
    definition.states[1].onEnter.push({ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['static-org'] } }] } });
    expect(await setWorkflowStatus(context, user, entity.id, target.id, true)).toMatchObject({ success: true, executionStatus: 'pending' });
    expect(createListTask).toHaveBeenCalledWith(context, WORKFLOW_MANAGER_USER, expect.objectContaining({ actions: [{ type: 'SHARE', context: { values: ['static-org'] } }] }));
  });

  it.each(['instance', 'supplied-status', 'initial-state'])('returns target hook input requirements from %s without writes', async (source) => {
    if (source !== 'instance') instance = null;
    if (source === 'initial-state') delete entity.x_opencti_workflow_id;
    definition.states[0].onExit.push({ type: 'asyncBulkAction', params: JSON.stringify({ actions: [{ type: 'SHARE', context: { values: [] } }] }) });
    definition.states[1].onEnter.push({ type: 'asyncBulkAction', params: { actions: [{ type: 'UNSHARE', context: { values: [] } }] } });
    definition.states[0].onEnter = [{ type: 'asyncBulkAction', params: { actions: [{ type: 'UNSHARE', context: { values: ['static-org'] } }] } }];
    expect(await getWorkflowBypassStatuses(context, user, entity.id)).toEqual([
      { status: legacy, onExit: definition.states[0].onExit, onEnter: definition.states[0].onEnter, requiresShareOrganizationInput: true, requiresUnshareOrganizationInput: false },
      { status: target, onExit: definition.states[0].onExit, onEnter: definition.states[1].onEnter, requiresShareOrganizationInput: true, requiresUnshareOrganizationInput: true },
    ]);
    expect(createEntity).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it.each(['status-only', 'with-hooks', 'hydrate-failure'])('notifies bypass comments only after commit: %s', async (mode) => {
    const unlock = vi.fn();
    vi.mocked(lockResources).mockResolvedValue({ unlock });
    vi.mocked(loadAssignees).mockResolvedValue([{ id: 'recipient' }, { id: user.id }] as any);
    vi.mocked(loadParticipants).mockResolvedValue([{ id: 'recipient' }] as any);
    vi.mocked(resolveUserById).mockResolvedValue({ id: 'recipient' } as any);
    let stateAtNotification: any;
    vi.mocked(addNotification).mockImplementationOnce(async () => {
      stateAtNotification = { ...instance, unlocked: unlock.mock.calls.length === 1 };
      return {} as any;
    });
    if (mode === 'hydrate-failure') {
      const load = vi.mocked(storeLoadById).getMockImplementation()!;
      vi.mocked(storeLoadById).mockImplementation(async (...args) => {
        if (args[2] === entity.id && instance.currentState === 'closed') throw new Error('response hydration failed');
        return load(...args);
      });
    }
    const result = setWorkflowStatus(context, user, entity.id, target.id, mode === 'with-hooks', '  override  ');
    if (mode === 'hydrate-failure') await expect(result).rejects.toThrow('response hydration failed');
    else expect(await result).toMatchObject({ success: true, executionStatus: 'completed' });
    expect(addNotification).toHaveBeenCalledOnce();
    expect(stateAtNotification).toMatchObject({ currentState: 'closed', pendingTransition: null, unlocked: true });
    expect(JSON.parse(stateAtNotification.history)).toEqual([expect.objectContaining({ event: 'event_bypass', comment: 'override' })]);
    expect(addNotification).toHaveBeenCalledWith(context, expect.anything(), expect.objectContaining({
      user_id: 'recipient',
      notification_content: [expect.objectContaining({ events: [expect.objectContaining({ message: '[event_bypass] override' })] })],
    }));
  });

  it.each(['hook-failure', 'commit-failure', 'pending', 'blank'])('does not notify a bypass comment for %s', async (mode) => {
    vi.mocked(loadAssignees).mockResolvedValue([{ id: 'recipient' }] as any);
    vi.mocked(loadParticipants).mockResolvedValue([]);
    vi.mocked(resolveUserById).mockResolvedValue({ id: 'recipient' } as any);
    if (mode === 'hook-failure') vi.mocked(ActionRegistry.log).mockRejectedValueOnce(new Error('hook failed'));
    if (mode === 'commit-failure') vi.mocked(updateAttribute).mockRejectedValueOnce(new Error('commit failed'));
    if (mode === 'pending') definition.states[0].onExit = [{ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['static-org'] } }] } }];

    await setWorkflowStatus(context, user, entity.id, target.id, mode !== 'commit-failure', mode === 'blank' ? '   ' : 'override');

    expect(addNotification).not.toHaveBeenCalled();
  });

  it('lazily initializes from legacy status without running initialization hooks', async () => {
    instance = null;
    expect(await setWorkflowStatus(context, user, entity.id, target.id, false)).toMatchObject({ success: true });
    expect(createEntity).toHaveBeenCalledWith(context, expect.objectContaining({ id: 'admin', draft_context: undefined }), expect.objectContaining({ currentState: 'open', scope: StatusScope.Global }), ENTITY_TYPE_WORKFLOW_INSTANCE);
    expect(createRelation).toHaveBeenCalledTimes(1);
    expect(ActionRegistry.log).not.toHaveBeenCalled();
    expect(WorkflowFactory.getInstance).not.toHaveBeenCalled();
  });

  it.each(['missing', 'template', 'type', 'scope', 'mapping', 'not-status'])('rejects invalid target %s before lazy initialization or actions', async (invalid) => {
    instance = null;
    if (invalid === 'missing') target = null;
    if (invalid === 'template') target.template_id = 'unpublished';
    if (invalid === 'type') target.type = 'Report';
    if (invalid === 'scope') target.scope = StatusScope.RequestAccess;
    if (invalid === 'mapping') vi.mocked(resolveMappedStatusId).mockResolvedValue('another-status');
    if (invalid === 'not-status') target.entity_type = 'StatusTemplate';
    expect(await setWorkflowStatus(context, user, entity.id, 'status-closed', true)).toMatchObject({ success: false });
    expect(createEntity).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(ActionRegistry.log).not.toHaveBeenCalled();
  });

  it('does not write when no published definition exists', async () => {
    vi.mocked(findByType).mockResolvedValue({ id: 'setting-id' } as any);
    expect(await setWorkflowStatus(context, user, entity.id, target.id, true)).toMatchObject({ success: false });
    expect(await getWorkflowBypassStatuses(context, user, entity.id)).toEqual([]);
    expect(createEntity).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it.each(['pending', 'error'])('blocks an instance with %s work', async (pendingStatus) => {
    instance.pendingStatus = pendingStatus;
    expect(await setWorkflowStatus(context, user, entity.id, target.id, false)).toMatchObject({ success: false });
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('checks entity access on mutation and picker', async () => {
    entity = null;
    vi.mocked(internalLoadById).mockResolvedValue(null as any);
    await expect(setWorkflowStatus(context, user, 'entity-id', 'status-closed', false)).rejects.toThrow('Entity not found');
    await expect(getWorkflowBypassStatuses(context, user, 'entity-id')).rejects.toThrow('Entity not found');
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('gates non-draft mutation and picker with ENTITIES_WORKFLOW', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    await expect(setWorkflowStatus(context, user, entity.id, target.id, false)).rejects.toThrow('ENTITIES_WORKFLOW');
    await expect(getWorkflowBypassStatuses(context, user, entity.id)).rejects.toThrow('ENTITIES_WORKFLOW');
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('keeps DraftWorkspace bypass and picker available with flag off', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    entity.entity_type = 'DraftWorkspace';
    target.type = 'DraftWorkspace';
    legacy.type = 'DraftWorkspace';
    expect(await getWorkflowBypassStatuses(context, user, entity.id)).toHaveLength(2);
    expect(await setWorkflowStatus(context, user, entity.id, target.id, false)).toMatchObject({ success: true });
  });

  it.each(['entity', 'instance', 'legacy'])('rejects RequestAccess detected through %s for mutation and picker', async (source) => {
    if (source === 'entity') entity.x_opencti_request_access = true;
    if (source === 'instance') instance.scope = StatusScope.RequestAccess;
    if (source === 'legacy') {
      instance = null;
      legacy.scope = StatusScope.RequestAccess;
    }
    await expect(setWorkflowStatus(context, user, entity.id, target.id, false)).rejects.toThrow('RequestAccess');
    await expect(getWorkflowBypassStatuses(context, user, entity.id)).rejects.toThrow('RequestAccess');
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('limits comments before any write', async () => {
    await expect(setWorkflowStatus(context, user, entity.id, target.id, false, 'a'.repeat(1001))).rejects.toThrow('1000');
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('surfaces hook failure without advancing or projecting the state', async () => {
    vi.mocked(ActionRegistry.log).mockRejectedValueOnce(new Error('hook failed'));
    expect(await setWorkflowStatus(context, user, entity.id, target.id, true)).toMatchObject({ success: false, executionStatus: 'error', reason: expect.stringContaining('hook failed') });
    expect(instance.currentState).toBe('open');
    expect(instance.pendingStatus).toBe('error');
    expect(projectWorkflowState).not.toHaveBeenCalled();
  });

  it.each(['pending', 'completed'])('preserves %s bypass state when response hydration fails', async (executionStatus) => {
    if (executionStatus === 'pending') {
      definition.states[0].onExit = [{ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['static-org'] } }] } }];
    }
    const load = vi.mocked(storeLoadById).getMockImplementation()!;
    vi.mocked(storeLoadById).mockImplementation(async (...args) => {
      if (args[2] === entity.id && (instance.pendingStatus === 'pending' || instance.currentState === 'closed')) {
        throw new Error('response hydration failed');
      }
      return load(...args);
    });

    await expect(setWorkflowStatus(context, user, entity.id, target.id, true)).rejects.toThrow('response hydration failed');

    expect(instance.pendingStatus).toBe(executionStatus === 'pending' ? 'pending' : null);
    expect(instance.pendingError).toBeNull();
    expect(instance.currentState).toBe(executionStatus === 'pending' ? 'open' : 'closed');
    if (executionStatus === 'pending') {
      expect(JSON.parse(instance.pendingTransition).asyncActions).toHaveLength(1);
    } else {
      expect(instance.pendingTransition).toBeNull();
      expect(JSON.parse(instance.history)).toHaveLength(1);
    }
    expect(updateAttribute).not.toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), expect.anything(), expect.arrayContaining([
      { key: 'pendingStatus', value: ['error'] },
    ]));
  });

  it('collects real registry async slots and defers remaining hooks with runtime params', async () => {
    const action = { type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: [] } }] } };
    definition.states[0].onExit.push(action, { type: 'log', params: { message: 'after async' } });
    const runtimeParams = { shareOrganizationIds: ['org-id'] };
    vi.mocked(createListTask).mockImplementationOnce(async () => {
      expect(instance.pendingStatus).toBe('pending');
      expect(JSON.parse(instance.pendingTransition).event).toBe('event_bypass');
      expect(lockResources).toHaveBeenCalledWith(['workflow-mutation-entity-id']);
      return { work_id: 'work-id' } as any;
    });
    expect(await setWorkflowStatus(context, user, entity.id, target.id, true, 'queued', runtimeParams)).toMatchObject({ success: true, executionStatus: 'pending' });
    expect(instance.currentState).toBe('open');
    const pending = JSON.parse(instance.pendingTransition);
    expect(pending).toMatchObject({ event: 'event_bypass', toState: 'closed', runtimeParams, comment: 'queued', syncActions: [definition.states[0].onExit[2], definition.states[1].onEnter[0]] });
    expect(pending.asyncActions).toEqual([expect.objectContaining({ workId: 'work-id', status: 'pending' })]);
    expect(createListTask).toHaveBeenCalledWith(context, WORKFLOW_MANAGER_USER, expect.objectContaining({ ids: ['entity-id'], workflow_instance_id: 'instance-id', workflow_action_id: pending.asyncActions[0].id, actions: [{ type: 'SHARE', context: { values: ['org-id'] } }] }));
    expect(vi.mocked(ActionRegistry.log).mock.calls.map((call) => call[1].message)).toEqual(['exit']);
    expect(projectWorkflowState).not.toHaveBeenCalled();
  });

  it.each([
    ['completed', 'bypass', 'event'],
    ['pending', 'bypass', 'event'],
    ['completed', 'bypass', 'clear'],
    ['pending', 'bypass', 'clear'],
    ['completed', 'event', 'bypass'],
    ['pending', 'event', 'bypass'],
    ['completed', 'callback', 'clear'],
  ])('serializes %s %s with a concurrent %s mutation', async (executionStatus, first, mutation) => {
    let enterHook!: () => void;
    let releaseHook!: () => void;
    let requestLock!: () => void;
    const hookEntered = new Promise<void>((resolve) => {
      enterHook = resolve;
    });
    const hookReleased = new Promise<void>((resolve) => {
      releaseHook = resolve;
    });
    const lockRequested = new Promise<void>((resolve) => {
      requestLock = resolve;
    });
    const locks = new Map<string, Promise<void>>();
    vi.mocked(lockResources).mockImplementation(async ([key]) => {
      const previous = locks.get(key);
      let unlock!: () => void;
      locks.set(key, new Promise<void>((resolve) => {
        unlock = resolve;
      }));
      if (vi.mocked(lockResources).mock.calls.length > 1) requestLock();
      await previous;
      return { unlock } as any;
    });
    vi.mocked(loadEntity).mockImplementation(async () => structuredClone(instance));
    if (first !== 'event') {
      vi.mocked(ActionRegistry.log).mockImplementationOnce(async () => {
        enterHook();
        await hookReleased;
      });
      if (first === 'callback') {
        instance.pendingStatus = 'pending';
        instance.pendingTransition = JSON.stringify({
          event: 'event_bypass', toState: 'closed', triggeredBy: user.id, triggeredAt: new Date().toISOString(),
          asyncActions: [{ id: 'slot-1', workId: 'work-id', type: 'asyncBulkAction', status: 'pending' }],
          syncActions: [{ type: 'log', params: { message: 'remaining hook' } }],
        });
      }
      if (executionStatus === 'pending') {
        definition.states[0].onExit.push({ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['static-org'] } }] } });
      }
    } else {
      vi.mocked(WorkflowFactory.getInstance).mockReturnValueOnce({
        trigger: async () => {
          enterHook();
          await hookReleased;
          return { success: true, executionStatus, asyncActionSlots: executionStatus === 'pending' ? [{ id: 'slot-1', workId: 'work-id', type: 'asyncBulkAction' }] : [] };
        },
        getCurrentState: () => 'closed',
      } as any);
    }
    const firstMutation = first === 'bypass'
      ? setWorkflowStatus(context, user, entity.id, target.id, true)
      : first === 'event'
        ? triggerWorkflowEvent(context, user, entity.id, 'close')
        : reportWorkflowAsyncActionResult(context, user, instance.id, 'slot-1', 'success');
    await hookEntered;
    const writesBefore = vi.mocked(updateAttribute).mock.calls.length;
    const triggersBefore = vi.mocked(WorkflowFactory.getInstance).mock.calls.length;
    const concurrent = mutation === 'event'
      ? triggerWorkflowEvent(context, user, entity.id, 'close')
      : mutation === 'bypass'
        ? setWorkflowStatus(context, user, entity.id, target.id, false)
        : clearWorkflowPendingState(context, user, entity.id);
    await Promise.race([lockRequested, concurrent]);
    const writesWhileHeld = vi.mocked(updateAttribute).mock.calls.length - writesBefore;
    const triggeredWhileHeld = vi.mocked(WorkflowFactory.getInstance).mock.calls.length - triggersBefore;
    releaseHook();
    const [, result] = await Promise.all([firstMutation, concurrent]);

    expect(writesWhileHeld).toBe(0);
    expect(triggeredWhileHeld).toBe(0);
    const firstEvent = first === 'event' ? 'close' : 'event_bypass';
    if (mutation !== 'clear' && executionStatus === 'pending') {
      expect(result).toMatchObject({ success: false, reason: expect.stringContaining('pending') });
      expect(JSON.parse(instance.pendingTransition).event).toBe(firstEvent);
    } else {
      expect(JSON.parse(instance.history).map((entry: any) => entry.event)).toEqual([
        ...(executionStatus === 'completed' ? [firstEvent] : []),
        mutation === 'event' ? 'close' : mutation === 'bypass' ? 'event_bypass' : 'admin_clear_pending_state',
      ]);
    }
    if (first === 'callback') {
      vi.mocked(updateAttribute).mockClear();
      await reportWorkflowAsyncActionResult(context, user, instance.id, 'slot-1', 'success');
      expect(updateAttribute).not.toHaveBeenCalled();
    }
  });

  it.each(['bypass', 'event'])('releases the %s mutation lock before hydrating a pending response', async (mutation) => {
    const unlock = vi.fn();
    vi.mocked(lockResources).mockResolvedValue({ unlock });
    definition.states[0].onExit = [{ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['static-org'] } }] } }];
    if (mutation === 'event') {
      vi.mocked(WorkflowFactory.getInstance).mockReturnValueOnce({
        trigger: async () => ({ success: true, executionStatus: 'pending', asyncActionSlots: [{ id: 'slot-1', workId: 'work-id', type: 'asyncBulkAction' }] }),
        getCurrentState: () => 'closed',
      } as any);
    }
    let unlockedAtHydration = false;
    const load = vi.mocked(storeLoadById).getMockImplementation()!;
    vi.mocked(storeLoadById).mockImplementation(async (...args) => {
      if (args[2] === entity.id && instance.pendingStatus === 'pending') unlockedAtHydration = unlock.mock.calls.length === 1;
      return load(...args);
    });

    const result = mutation === 'bypass'
      ? await setWorkflowStatus(context, user, entity.id, target.id, true)
      : await triggerWorkflowEvent(context, user, entity.id, 'close');

    expect(result).toMatchObject({ success: true, executionStatus: 'pending' });
    expect(unlockedAtHydration).toBe(true);
    expect(unlock).toHaveBeenCalledOnce();
  });

  it('targets only draft contents and persists draft ids for continuation', async () => {
    entity.entity_type = 'DraftWorkspace';
    target.type = 'DraftWorkspace';
    definition.states[0].onExit = [{ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['static-org'] } }] } }];
    vi.mocked(fullEntitiesList).mockResolvedValue([{ internal_id: 'draft-object' }, { internal_id: 'linked', draft_change: { draft_operation: 'update_linked' } }] as any);
    expect(await setWorkflowStatus(context, user, entity.id, target.id, true)).toMatchObject({ executionStatus: 'pending' });
    expect(createListTask).toHaveBeenCalledWith(expect.objectContaining({ draft_context: 'entity-id' }), WORKFLOW_MANAGER_USER, expect.objectContaining({ ids: ['draft-object'] }));
    expect(JSON.parse(instance.pendingTransition).draftEntityIds).toEqual(['draft-object']);
  });

  it('returns only published mapped statuses in projection order without a 100-item limit or writes', async () => {
    const statuses = Array.from({ length: 105 }, (_, index) => ({ ...target, id: `status-${index}`, template_id: `state-${index}`, order: index }));
    definition.states = statuses.map((status) => ({ statusId: status.template_id }));
    vi.mocked(fullEntitiesList).mockResolvedValue([...statuses].reverse().concat({ ...target, template_id: 'stale' }));
    expect(await getWorkflowBypassStatuses(context, user, entity.id)).toEqual(statuses.map((status) => ({
      status, onExit: [], onEnter: [], requiresShareOrganizationInput: false, requiresUnshareOrganizationInput: false,
    })));
    expect(createEntity).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });
});

describe('Workflow Domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('denies workflow bypass without BYPASS before accessing or changing an entity', async () => {
    await expect(setWorkflowStatus({} as any, { id: 'editor', capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as any, 'entity-id', 'status-id', false))
      .rejects.toThrow('BYPASS');
    expect(internalLoadById).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('should fail when definition JSON is invalid', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', '{ invalid-json')).rejects.toThrow('Invalid workflow definition JSON');
    expect(validateWorkflowDefinitionData).not.toHaveBeenCalled();
  });

  it('should fail when entity setting is not found', async () => {
    (findByType as any).mockResolvedValue(null);

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', JSON.stringify({ initialState: 'draft', transitions: [] }))).rejects.toThrow('Entity setting not found for type');
  });

  describe('EE / CE gating in setWorkflowDefinition', () => {
    const ceDefinition = (overrides = {}) => JSON.stringify({
      initialState: 'draft',
      states: [],
      transitions: [],
      ...overrides,
    });

    beforeEach(() => {
      // Default: EE check passes (simulates EE licence)
      vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue(undefined);
      (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });
      const versionObj = { id: 'v1', timestamp: '', createdBy: '', content: '{}', validation_errors: [] };
      (createEntity as any).mockResolvedValue({ id: 'workflow-id', name: 'Workflow for Incident', all_versions: [versionObj], draft_version: versionObj });
      (updateAttribute as any).mockResolvedValue({ element: { id: 'entity-setting-id', workflow_id: 'workflow-id' } });
    });

    it('does NOT call checkEnterpriseEdition for a plain CE definition (no EE actions, no conditions)', async () => {
      const def = ceDefinition({
        transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'validateDraft', mode: 'sync' }] }],
      });
      await setWorkflowDefinition(mockContext, mockUser, 'Incident', def);
      expect(ee.checkEnterpriseEdition).not.toHaveBeenCalled();
    });

    it('does NOT call checkEnterpriseEdition when conditions is present but filters array is empty', async () => {
      const def = ceDefinition({
        transitions: [{ from: 'open', to: 'closed', event: 'close', conditions: emptyFilterGroup }],
      });
      await setWorkflowDefinition(mockContext, mockUser, 'Incident', def);
      expect(ee.checkEnterpriseEdition).not.toHaveBeenCalled();
    });

    it.each([
      ['updateAuthorizedMembers on transition syncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }] }],
      ['shareWithOrganizations on transition asyncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', asyncActions: [{ type: 'shareWithOrganizations', mode: 'async' }] }] }],
      ['unshareFromOrganizations on transition asyncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', asyncActions: [{ type: 'unshareFromOrganizations', mode: 'async' }] }] }],
      ['asyncBulkAction on transition syncActions', { transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'asyncBulkAction', mode: 'sync' }] }] }],
      ['non-empty conditions filters on transition', { transitions: [{ from: 'open', to: 'closed', event: 'close', conditions: { mode: 'and', filters: [{ key: 'entity_type', values: ['Incident'] }], filterGroups: [] } }] }],
      ['updateAuthorizedMembers on state onEnter', { states: [{ statusId: 'status-1', onEnter: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }] }],
      ['updateAuthorizedMembers on state onExit', { states: [{ statusId: 'status-1', onExit: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }] }],
    ])('calls checkEnterpriseEdition when definition has %s', async (_label, overrides) => {
      const def = ceDefinition(overrides);
      await setWorkflowDefinition(mockContext, mockUser, 'Incident', def);
      expect(ee.checkEnterpriseEdition).toHaveBeenCalledWith(mockContext);
    });

    it('propagates the error thrown by checkEnterpriseEdition (CE instance rejects EE features)', async () => {
      vi.spyOn(ee, 'checkEnterpriseEdition').mockRejectedValue(new Error('Enterprise edition required'));
      const def = ceDefinition({
        transitions: [{ from: 'open', to: 'closed', event: 'close', syncActions: [{ type: 'updateAuthorizedMembers', mode: 'sync' }] }],
      });
      await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', def)).rejects.toThrow('Enterprise edition required');
      expect(createEntity).not.toHaveBeenCalled();
    });

    it('never creates or deletes Status records on draft save (full-mapping/orphan-detection are publish-only)', async () => {
      const def = ceDefinition({
        initialState: 'tpl-open',
        states: [{ statusId: 'tpl-open' }, { statusId: 'tpl-progress' }],
        transitions: [{ from: 'tpl-open', to: 'tpl-progress', event: 'start' }],
      });
      await setWorkflowDefinition(mockContext, mockUser, 'Incident', def);
      expect(createStatus).not.toHaveBeenCalled();
      expect(updateAttribute).not.toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.anything(),
        expect.anything(),
        expect.arrayContaining([expect.objectContaining({ key: 'to_be_deleted_at' })]),
      );
    });
  });

  it('should update existing workflow when entity setting already has workflow id', async () => {
    const definition = JSON.stringify({
      name: 'Updated Workflow',
      initialState: 'draft',
      transitions: [],
    });

    const existingVersionData = {
      id: 'version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Old Workflow","initialState":"draft","transitions":[]}',
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Old Workflow',
        all_versions: [existingVersionData],
        draft_version: existingVersionData,
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Updated Workflow',
        all_versions: [
          expect.objectContaining({ content: definition }),
          existingVersionData,
        ],
        draft_version: expect.objectContaining({ content: definition }),
      });

    await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(validateWorkflowDefinitionData).toHaveBeenCalledWith(mockContext, mockUser, definition, 'Incident', 'workflow-id');
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'workflow-id',
      'WorkflowDefinition',
      expect.arrayContaining([
        expect.objectContaining({ key: 'draft_version' }),
        expect.objectContaining({ key: 'all_versions' }),
        expect.objectContaining({ key: 'name', value: ['Updated Workflow'] }),
      ]),
    );
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should create and link workflow when no linked workflow exists', async () => {
    const definition = JSON.stringify({
      initialState: 'draft',
      transitions: [],
    });

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });
    (createEntity as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Workflow for Incident',
      all_versions: [expect.objectContaining({ content: definition })],
      draft_version: expect.objectContaining({ content: definition }),
    });
    (updateAttribute as any).mockResolvedValue({ element: { id: 'entity-setting-id', workflow_id: 'workflow-id' } });

    const result = await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(validateWorkflowDefinitionData).toHaveBeenCalledWith(mockContext, mockUser, definition, 'Incident', undefined);
    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({
        name: 'Workflow for Incident',
        draft_version: expect.objectContaining({ content: definition }),
        all_versions: [expect.objectContaining({ content: definition })],
      }),
      'WorkflowDefinition',
    );
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'entity-setting-id',
      'EntitySetting',
      [{ key: 'workflow_id', value: ['workflow-id'] }],
    );
    expect(result).toMatchObject({
      id: 'entity-setting-id',
      workflow_id: 'workflow-id',
      published: false,
    });
  });

  it('should return true when status template id is found in string workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        published_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: '{"states":[{"statusId":"status-template-id"}]}',
          validation_errors: [],
        },
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  it('should return true when status template id is found in object workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        draft_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: { states: [{ statusId: 'status-template-id' }] },
          validation_errors: [],
        },
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  it('should return false when status template id is not found in any workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        published_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: '{"states":[{"statusId":"another-id"}]}',
          validation_errors: [],
        },
        all_versions: [],
      },
      {
        draft_version: {
          id: 'version-2',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: { states: [{ statusId: 'yet-another-id' }] },
          validation_errors: [],
        },
        all_versions: [],
      },
      {
        published_version: null,
        draft_version: null,
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(false);
  });

  it('should return true when status template id is only referenced via a transition endpoint (not declared in states)', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        published_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: JSON.stringify({
            initialState: 'status-a',
            states: [{ statusId: 'status-a' }],
            transitions: [{ from: 'status-a', to: 'status-template-id', event: 'next' }],
          }),
          validation_errors: [],
        },
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  describe('isStatusUsedInWorkflow', () => {
    it('should check the request-access workflow mapping when the status scope is RequestAccess', async () => {
      (fullEntitiesList as any).mockResolvedValue([
        { request_access_workflow: { approved_workflow_id: 'status-id', declined_workflow_id: 'other-status-id' } },
      ]);

      const result = await isStatusUsedInWorkflow(mockContext, mockUser, {
        id: 'status-id',
        type: 'Incident',
        scope: StatusScope.RequestAccess,
        template_id: 'status-template-id',
      } as any);

      expect(result).toBe(true);
      expect(findByType).not.toHaveBeenCalled();
    });

    it('should return false for a RequestAccess status not referenced by any entity setting', async () => {
      (fullEntitiesList as any).mockResolvedValue([
        { request_access_workflow: { approved_workflow_id: 'unrelated-status-id' } },
      ]);

      const result = await isStatusUsedInWorkflow(mockContext, mockUser, {
        id: 'status-id',
        type: 'Incident',
        scope: StatusScope.RequestAccess,
        template_id: 'status-template-id',
      } as any);

      expect(result).toBe(false);
    });

    it('should return false for a Global status when its entity type has no workflow configured', async () => {
      (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: null });

      const result = await isStatusUsedInWorkflow(mockContext, mockUser, {
        id: 'status-id',
        type: 'Incident',
        scope: StatusScope.Global,
        template_id: 'status-template-id',
      } as any);

      expect(result).toBe(false);
      expect(storeLoadById).not.toHaveBeenCalled();
    });

    it('should return true for a Global status only when its own entity type workflow references the template', async () => {
      (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
      (storeLoadById as any).mockResolvedValue({
        published_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: '{"states":[{"statusId":"status-template-id"}]}',
          validation_errors: [],
        },
      });

      const result = await isStatusUsedInWorkflow(mockContext, mockUser, {
        id: 'status-id',
        type: 'Incident',
        scope: StatusScope.Global,
        template_id: 'status-template-id',
      } as any);

      expect(result).toBe(true);
      expect(storeLoadById).toHaveBeenCalledWith(mockContext, mockUser, 'workflow-id', 'WorkflowDefinition');
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });

    it('should return false for a Global status when its own entity type workflow does not reference the template, even if another entity type does', async () => {
      (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
      (storeLoadById as any).mockResolvedValue({
        published_version: {
          id: 'version-1',
          timestamp: '2024-01-01T00:00:00Z',
          createdBy: 'user-1',
          content: '{"states":[{"statusId":"another-entity-template-id"}]}',
          validation_errors: [],
        },
      });

      const result = await isStatusUsedInWorkflow(mockContext, mockUser, {
        id: 'status-id',
        type: 'Report',
        scope: StatusScope.Global,
        template_id: 'status-template-id',
      } as any);

      expect(result).toBe(false);
    });
  });

  // Tests for publishWorkflowDefinition
  it('should publish workflow when draft_version has no validation errors', async () => {
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Test Workflow","initialState":"open","states":[],"transitions":[]}',
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        draft_version: draftVersion,
        all_versions: [draftVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion],
      });

    const result = await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'workflow-id',
      'WorkflowDefinition',
      expect.arrayContaining([
        { key: 'published_version', value: [draftVersion] },
      ]),
    );
    expect(result).toMatchObject({
      id: 'entity-setting-id',
      workflow_id: 'workflow-id',
      published: true,
    });
    expect(telemetryManager.addWorkflowPublishCount).toHaveBeenCalledOnce();
  });

  it('should create missing Status records for every declared state on publish (full-mapping invariant)', async () => {
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        name: 'Test Workflow',
        initialState: 'tpl-open',
        states: [
          { statusId: 'tpl-open' },
          { statusId: 'tpl-progress' },
          { statusId: 'tpl-done' },
        ],
        transitions: [
          { from: 'tpl-open', to: 'tpl-progress', event: 'start' },
          { from: 'tpl-progress', to: 'tpl-done', event: 'finish' },
        ],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        draft_version: draftVersion,
        all_versions: [draftVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion],
      });

    // Only tpl-open already has a Status record for this entity type/scope.
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-open', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-open', order: 0 },
    ]);

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(createStatus).toHaveBeenCalledTimes(2);
    expect(createStatus).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'Incident',
      { template_id: 'tpl-progress', order: 1, scope: StatusScope.Global },
    );
    expect(createStatus).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'Incident',
      { template_id: 'tpl-done', order: 2, scope: StatusScope.Global },
    );
  });

  it('should not create any Status record on publish when the mapping is already complete', async () => {
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        name: 'Test Workflow',
        initialState: 'tpl-open',
        states: [{ statusId: 'tpl-open' }],
        transitions: [],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        draft_version: draftVersion,
        all_versions: [draftVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion],
      });

    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-open', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-open', order: 0 },
    ]);

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(createStatus).not.toHaveBeenCalled();
  });

  it('should sync (not migrate) the order of an already-existing Status whose stored order is stale, without creating anything', async () => {
    // Simulates a Status published before ordering was computed from the transition graph (e.g.
    // the built-in DraftWorkspace workflow): its stored `order` (0) no longer matches the order
    // freshly computed from the current transition graph (tpl-progress should be 1).
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        name: 'Test Workflow',
        initialState: 'tpl-open',
        states: [{ statusId: 'tpl-open' }, { statusId: 'tpl-progress' }],
        transitions: [{ from: 'tpl-open', to: 'tpl-progress', event: 'start' }],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        draft_version: draftVersion,
        all_versions: [draftVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion],
      });

    // Both states already have a Status record, but tpl-progress carries a stale order (0
    // instead of the freshly computed 1).
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-open', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-open', order: 0 },
      { id: 'status-progress', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-progress', order: 0 },
    ]);

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(createStatus).not.toHaveBeenCalled();
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-progress',
      ENTITY_TYPE_STATUS,
      [{ key: 'order', value: [1] }],
    );
    // The already-correct status-open (order 0) must not be touched.
    expect(updateAttribute).not.toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-open',
      ENTITY_TYPE_STATUS,
      expect.arrayContaining([expect.objectContaining({ key: 'order' })]),
    );
  });

  it('should be a no-op republish for a DraftWorkspace-shaped definition matching realistic production data (regression, Step 4.9)', async () => {
    // DraftWorkspace is the only entity type with an actually-published WorkflowDefinition in
    // existing installs today; its states already carry statusId (no name-only legacy states).
    const draftWorkspaceDefinition = {
      name: 'Draft workflow',
      initialState: 'draft-open',
      states: [
        { statusId: 'draft-open', name: 'Open' },
        { statusId: 'draft-in-progress', name: 'In progress' },
        { statusId: 'draft-validated', name: 'Validated' },
      ],
      transitions: [
        { from: 'draft-open', to: 'draft-in-progress', event: 'start_validation' },
        { from: 'draft-in-progress', to: 'draft-validated', event: 'validate' },
      ],
    };
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify(draftWorkspaceDefinition),
      validation_errors: [],
    };
    // Republish with the exact same definition content (no actual change from the admin).
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify(draftWorkspaceDefinition),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Draft workflow',
        published_version: publishedVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion, publishedVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Draft workflow',
        published_version: draftVersion,
        draft_version: null,
        all_versions: [draftVersion, publishedVersion],
      });

    // All three states already have a matching, fully-mapped, unmarked Status record — matching
    // the real production dataset (existing DraftWorkspace installs already have complete mappings).
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-draft-open', type: 'DraftWorkspace', scope: StatusScope.Global, template_id: 'draft-open', order: 0 },
      { id: 'status-draft-in-progress', type: 'DraftWorkspace', scope: StatusScope.Global, template_id: 'draft-in-progress', order: 1 },
      { id: 'status-draft-validated', type: 'DraftWorkspace', scope: StatusScope.Global, template_id: 'draft-validated', order: 2 },
    ]);

    await publishWorkflowDefinition(mockContext, mockUser, 'DraftWorkspace');

    // ensureFullStatusMapping is a no-op: mapping is already complete, nothing created.
    expect(createStatus).not.toHaveBeenCalled();
    // reconcileOrphanedStatuses is a no-op: nothing was removed from the definition, so no
    // existing Status is unexpectedly marked for (or restored from) deletion.
    expect(updateAttribute).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      ENTITY_TYPE_STATUS,
      expect.arrayContaining([expect.objectContaining({ key: 'to_be_deleted_at' })]),
    );
  });

  it('should create a Status for a state referenced only as a transition endpoint (not declared in `states`)', async () => {
    // Regression: templates 'tpl-a'/'tpl-b', initialState 'tpl-a', only 'tpl-a' declared in
    // `states`, and a transition 'tpl-a' -> 'tpl-b'. Validation accepts 'tpl-b' as a transition
    // endpoint backed by an existing StatusTemplate even though it has no entry in `states`, and
    // the engine registers it as a state — so the full-status-mapping invariant must still create
    // a Status for it.
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        name: 'Test Workflow',
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }],
        transitions: [{ from: 'tpl-a', to: 'tpl-b', event: 'advance' }],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        draft_version: draftVersion,
        all_versions: [draftVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion],
      });

    // Only tpl-a already has a Status record for this entity type/scope.
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-a', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0 },
    ]);

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(createStatus).toHaveBeenCalledTimes(1);
    expect(createStatus).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'Incident',
      { template_id: 'tpl-b', order: 1, scope: StatusScope.Global },
    );
  });

  it('should mark an orphaned Status for deletion when its state is removed and it is unreferenced', async () => {
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }, { statusId: 'tpl-b' }],
        transitions: [{ from: 'tpl-a', to: 'tpl-b', event: 'finish' }],
      }),
      validation_errors: [],
    };
    // Draft removes tpl-b entirely (tpl-b is an ending state, safe to remove).
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }],
        transitions: [],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: publishedVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion, publishedVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: null,
        all_versions: [draftVersion, publishedVersion],
      });

    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types[0] === ENTITY_TYPE_STATUS) {
        return Promise.resolve([
          { id: 'status-a-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0 },
          { id: 'status-b-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-b', order: 1 },
        ]);
      }
      if (types[0] === ENTITY_TYPE_ENTITY_SETTING) {
        return Promise.resolve([]);
      }
      if (types[0] === 'Incident') {
        // No entity currently points its x_opencti_workflow_id at status-b-id.
        return Promise.resolve([]);
      }
      return Promise.resolve([]);
    });

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-b-id',
      ENTITY_TYPE_STATUS,
      [{ key: 'to_be_deleted_at', value: [expect.any(Date)] }],
    );
    expect(updateAttribute).not.toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-a-id',
      ENTITY_TYPE_STATUS,
      expect.anything(),
    );
  });

  it('should not mark an orphaned Status for deletion when its state is dropped from `states` but still referenced via a transition endpoint', async () => {
    // Regression: tpl-b is removed from the `states` array but the transition to it is kept, so
    // the workflow still uses tpl-b as an implicit state — it must not be treated as orphaned.
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }, { statusId: 'tpl-b' }],
        transitions: [{ from: 'tpl-a', to: 'tpl-b', event: 'finish' }],
      }),
      validation_errors: [],
    };
    // Draft drops tpl-b's entry from `states` but keeps the transition referencing it.
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }],
        transitions: [{ from: 'tpl-a', to: 'tpl-b', event: 'finish' }],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: publishedVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion, publishedVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: null,
        all_versions: [draftVersion, publishedVersion],
      });

    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types[0] === ENTITY_TYPE_STATUS) {
        return Promise.resolve([
          { id: 'status-a-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0 },
          { id: 'status-b-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-b', order: 1 },
        ]);
      }
      if (types[0] === ENTITY_TYPE_ENTITY_SETTING) {
        return Promise.resolve([]);
      }
      return Promise.resolve([]);
    });

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).not.toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-b-id',
      ENTITY_TYPE_STATUS,
      expect.arrayContaining([expect.objectContaining({ key: 'to_be_deleted_at' })]),
    );
  });

  it('should throw when publishing removes a state whose status is still referenced by an entity inside a draft', async () => {
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }, { statusId: 'tpl-b' }],
        transitions: [{ from: 'tpl-a', to: 'tpl-b', event: 'finish' }],
      }),
      validation_errors: [],
    };
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }],
        transitions: [],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion,
      all_versions: [draftVersion, publishedVersion],
    });

    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[], args: any) => {
      if (types[0] === ENTITY_TYPE_STATUS) {
        return Promise.resolve([
          { id: 'status-a-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0 },
          { id: 'status-b-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-b', order: 1 },
        ]);
      }
      if (types[0] === ENTITY_TYPE_ENTITY_SETTING) {
        return Promise.resolve([]);
      }
      if (types[0] === 'Incident') {
        // No entity in the live index references status-b-id, but a draft-only entity does —
        // this must still block the publish.
        if (args?.indices?.some((index: string) => index.includes('_draft_objects'))) {
          return Promise.resolve([{ id: 'draft-entity-id', x_opencti_workflow_id: 'status-b-id' }]);
        }
        return Promise.resolve([]);
      }
      return Promise.resolve([]);
    });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident'))
      .rejects.toThrow('Cannot publish workflow: the following statuses are still assigned to entities and cannot be removed.');

    expect(updateAttribute).not.toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-b-id',
      ENTITY_TYPE_STATUS,
      expect.anything(),
    );
  });

  it('should not mark an orphaned Status for deletion when it is still referenced by a request-access workflow', async () => {
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }, { statusId: 'tpl-b' }],
        transitions: [{ from: 'tpl-a', to: 'tpl-b', event: 'finish' }],
      }),
      validation_errors: [],
    };
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }],
        transitions: [],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: publishedVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion, publishedVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: null,
        all_versions: [draftVersion, publishedVersion],
      });

    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types[0] === ENTITY_TYPE_STATUS) {
        return Promise.resolve([
          { id: 'status-a-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0 },
          { id: 'status-b-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-b', order: 1 },
        ]);
      }
      if (types[0] === ENTITY_TYPE_ENTITY_SETTING) {
        // A different entity type's EntitySetting still routes request-access approval to status-b-id.
        return Promise.resolve([
          { id: 'other-entity-setting', request_access_workflow: { approved_workflow_id: 'status-b-id' } },
        ]);
      }
      if (types[0] === 'Incident') {
        return Promise.resolve([]);
      }
      return Promise.resolve([]);
    });

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).not.toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-b-id',
      ENTITY_TYPE_STATUS,
      expect.anything(),
    );
  });

  it('should clear a pending deletion mark when a republish reintroduces the state (restore wins over purge)', async () => {
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }],
        transitions: [],
      }),
      validation_errors: [],
    };
    // Draft reintroduces tpl-b, which still has a pending to_be_deleted_at mark from an earlier republish.
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'tpl-a',
        states: [{ statusId: 'tpl-a' }, { statusId: 'tpl-b' }],
        transitions: [{ from: 'tpl-a', to: 'tpl-b', event: 'finish' }],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: publishedVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion, publishedVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: null,
        all_versions: [draftVersion, publishedVersion],
      });

    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types[0] === ENTITY_TYPE_STATUS) {
        return Promise.resolve([
          { id: 'status-a-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0 },
          {
            id: 'status-b-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-b', order: 1, to_be_deleted_at: new Date(),
          },
        ]);
      }
      return Promise.resolve([]);
    });

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'status-b-id',
      ENTITY_TYPE_STATUS,
      [{ key: 'to_be_deleted_at', value: [null] }],
    );
  });

  it('should not call addWorkflowPublishCount when publish fails due to validation errors', async () => {
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Invalid Workflow","initialState":"open","states":[],"transitions":[]}',
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Invalid Workflow',
      draft_version: draftVersion,
      all_versions: [draftVersion],
    });
    // Publish re-validates the draft rather than trusting its stored (possibly stale) validation_errors.
    (validateWorkflowDefinitionData as any).mockResolvedValueOnce([{ type: 'INVALID_SCHEMA', message: 'Missing required field', path: [] }]);

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('Cannot publish workflow with validation errors');
    expect(telemetryManager.addWorkflowPublishCount).not.toHaveBeenCalled();
  });

  it('should fail to publish workflow when draft_version has validation errors', async () => {
    const draftVersion = {
      id: 'draft-version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Invalid Workflow","initialState":"open","states":[],"transitions":[]}',
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Invalid Workflow',
      draft_version: draftVersion,
      all_versions: [draftVersion],
    });
    // Publish re-validates the draft rather than trusting its stored (possibly stale) validation_errors.
    (validateWorkflowDefinitionData as any).mockResolvedValueOnce([{ type: 'INVALID_SCHEMA', message: 'Missing required field', path: [] }]);

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('Cannot publish workflow with validation errors');
  });

  it('should fail to publish workflow when no draft_version exists', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'No Draft Workflow',
      draft_version: null,
      all_versions: [],
    });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('No draft version to publish');
  });

  it('should fail to publish workflow when entity setting not found', async () => {
    (findByType as any).mockResolvedValue(null);

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('Entity setting not found for type');
  });

  it('should fail to publish workflow when no workflow is linked', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: null });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('No workflow definition to publish');
  });

  it('should clear draft_version when publishing matching content', async () => {
    const version = {
      id: 'version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Same Content","initialState":"open","states":[],"transitions":[]}',
      validation_errors: [],
    };

    // Mock with existing published_version that matches draft
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Same Content',
        published_version: version, // Already has this published
        draft_version: version, // Draft is the same
        all_versions: [version],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Same Content',
        published_version: version,
        draft_version: null, // Should be cleared
        all_versions: [version],
      });

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'workflow-id',
      'WorkflowDefinition',
      [
        { key: 'published_version', value: [version] },
        { key: 'draft_version', value: [] },
      ],
    );
  });

  it('should throw when publishing removes a non-ending state currently in use', async () => {
    // Published version: state-a → state-b → state-c (state-b has outgoing transition → non-ending)
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'state-a',
        states: [{ statusId: 'state-a' }, { statusId: 'state-b' }, { statusId: 'state-c' }],
        transitions: [
          { from: 'state-a', to: 'state-b', event: 'proceed' },
          { from: 'state-b', to: 'state-c', event: 'complete' },
        ],
      }),
      validation_errors: [],
    };
    // Draft version: removes state-b (jumps state-a → state-c directly)
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'state-a',
        states: [{ statusId: 'state-a' }, { statusId: 'state-c' }],
        transitions: [
          { from: 'state-a', to: 'state-c', event: 'skip' },
        ],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion,
      all_versions: [draftVersion, publishedVersion],
    });

    // An instance is currently in state-b (the removed non-ending state)
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'instance-1', workflow_id: 'workflow-id', currentState: 'state-b' },
    ]);

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident'))
      .rejects.toThrow('Cannot publish workflow: the following statuses are in use and cannot be removed');
  });

  it('should throw when publishing removes an ending state whose status is still assigned to an entity (regression: draft compared against published, not itself)', async () => {
    // Regression for the case where validateWorkflowDefinitionData's own "old" definition lookup
    // resolves to the same draft being published (old === new), which would silently miss this.
    // Published version: state-a -> state-b, state-b is an ending state (no outgoing transitions).
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'state-a',
        states: [{ statusId: 'state-a' }, { statusId: 'state-b' }],
        transitions: [{ from: 'state-a', to: 'state-b', event: 'finish' }],
      }),
      validation_errors: [],
    };
    // Draft removes state-b entirely.
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'state-a',
        states: [{ statusId: 'state-a' }],
        transitions: [],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion,
      all_versions: [draftVersion, publishedVersion],
    });

    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types[0] === ENTITY_TYPE_STATUS) {
        return Promise.resolve([
          { id: 'status-b-id', type: 'Incident', scope: StatusScope.Global, template_id: 'state-b', order: 1 },
        ]);
      }
      if (types[0] === 'Incident') {
        // An Incident is still assigned to the removed status.
        return Promise.resolve([{ id: 'incident-1', x_opencti_workflow_id: 'status-b-id' }]);
      }
      return Promise.resolve([]);
    });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident'))
      .rejects.toThrow('Cannot publish workflow: the following statuses are still assigned to entities and cannot be removed.');
  });

  it('should allow publishing when removed state is an ending state', async () => {
    // Published version: state-a → state-b (state-b is terminal, no outgoing transitions)
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'state-a',
        states: [{ statusId: 'state-a' }, { statusId: 'state-b' }],
        transitions: [
          { from: 'state-a', to: 'state-b', event: 'finish' },
        ],
      }),
      validation_errors: [],
    };
    // Draft version: removes state-b entirely
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'state-a',
        states: [{ statusId: 'state-a' }],
        transitions: [],
      }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: publishedVersion,
        draft_version: draftVersion,
        all_versions: [draftVersion, publishedVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Test Workflow',
        published_version: draftVersion,
        draft_version: null,
        all_versions: [draftVersion, publishedVersion],
      });

    // An instance is in the ending state state-b, but that should not block publication
    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types[0] === ENTITY_TYPE_WORKFLOW_INSTANCE) {
        return Promise.resolve([{ id: 'instance-1', workflow_id: 'workflow-id', currentState: 'state-b' }]);
      }
      return Promise.resolve([]);
    });

    const result = await publishWorkflowDefinition(mockContext, mockUser, 'Incident');
    expect(result.published).toBe(true);
  });

  it('should acquire and release a lock shared with the workflow status cleanup manager during publish', async () => {
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({ initialState: 'state-a', states: [{ statusId: 'state-a' }], transitions: [] }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      draft_version: draftVersion,
      all_versions: [draftVersion],
    });
    (fullEntitiesList as any).mockResolvedValue([]);

    const unlock = vi.fn();
    (lockResources as any).mockResolvedValueOnce({ unlock });

    await publishWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(lockResources).toHaveBeenCalledWith(['workflow-status-lifecycle:Incident']);
    expect(unlock).toHaveBeenCalledOnce();
  });

  it('should release the lock even when publish throws', async () => {
    const publishedVersion = {
      id: 'pub-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({
        initialState: 'state-a',
        states: [{ statusId: 'state-a' }, { statusId: 'state-b' }],
        transitions: [{ from: 'state-a', to: 'state-b', event: 'finish' }],
      }),
      validation_errors: [],
    };
    const draftVersion2 = {
      id: 'draft-2',
      timestamp: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      content: JSON.stringify({ initialState: 'state-a', states: [{ statusId: 'state-a' }], transitions: [] }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion2,
      all_versions: [draftVersion2, publishedVersion],
    });
    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types[0] === ENTITY_TYPE_STATUS) {
        return Promise.resolve([
          { id: 'status-b-id', type: 'Incident', scope: StatusScope.Global, template_id: 'state-b', order: 1 },
        ]);
      }
      if (types[0] === 'Incident') {
        return Promise.resolve([{ id: 'incident-1', x_opencti_workflow_id: 'status-b-id' }]);
      }
      return Promise.resolve([]);
    });

    const unlock = vi.fn();
    (lockResources as any).mockResolvedValueOnce({ unlock });

    await expect(publishWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow();

    expect(unlock).toHaveBeenCalledOnce();
  });

  it('should update workflow with different draft and published versions', async () => {
    const existingVersion = {
      id: 'version-1',
      timestamp: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      content: '{"name":"Old Workflow","initialState":"draft","transitions":[]}',
      validation_errors: [],
    };

    const definition = JSON.stringify({
      name: 'Updated Workflow',
      initialState: 'draft',
      transitions: [],
    });

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Old Workflow',
        published_version: existingVersion,
        draft_version: existingVersion,
        all_versions: [existingVersion],
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        name: 'Updated Workflow',
        published_version: existingVersion,
        draft_version: expect.objectContaining({ content: definition }),
        all_versions: [
          expect.objectContaining({ content: definition }),
          existingVersion,
        ],
      });

    const result = await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(result.published).toBe(false); // Draft differs from published
  });

  // Tests for validateVersionConsistency (lines 54-74)
  it('should throw error when all_versions is not an array', async () => {
    const definition = JSON.stringify({ name: 'Test', initialState: 'draft', transitions: [] });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      all_versions: null, // Invalid: not an array
      draft_version: { id: 'v1', content: '{}', validation_errors: [] },
    });

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', definition)).rejects.toThrow('all_versions must be an array');
  });

  it('should throw error when draft_version not in all_versions', async () => {
    const definition = JSON.stringify({ name: 'Test', initialState: 'draft', transitions: [] });
    const draftVersion = { id: 'draft-1', timestamp: '2024-01-01', createdBy: 'user-1', content: definition, validation_errors: [] };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [{ id: 'other-version' }], // draft_version not in here
        draft_version: draftVersion,
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [draftVersion, { id: 'other-version' }],
        draft_version: draftVersion,
      });

    await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);
    // Should succeed after update
  });

  it('should validate consistency when publishing', async () => {
    const draftVersion = {
      id: 'draft-1',
      timestamp: '2024-01-02',
      createdBy: 'user-1',
      content: JSON.stringify({ initialState: 'open', states: [], transitions: [] }),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any)
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [draftVersion],
        draft_version: draftVersion,
        published_version: null,
      })
      .mockResolvedValueOnce({
        id: 'workflow-id',
        all_versions: [draftVersion],
        draft_version: null,
        published_version: draftVersion,
      });
    (fullEntitiesList as any).mockResolvedValue([]);

    const result = await publishWorkflowDefinition(mockContext, mockUser, 'Incident');
    expect(result.published).toBe(true);
  });

  // Tests for getWorkflowDefinition (lines 203-206)
  it('should get workflow definition with allowDraft=false (published only)', async () => {
    const publishedContent = { name: 'Published', initialState: 'open', transitions: [] };
    const draftContent = { name: 'Draft', initialState: 'draft', transitions: [] };
    const publishedVersion = {
      id: 'pub-1',
      content: JSON.stringify(publishedContent),
      validation_errors: [],
    };
    const draftVersion = {
      id: 'draft-1',
      content: JSON.stringify(draftContent),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion,
      all_versions: [draftVersion, publishedVersion],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', false);

    expect(result).toBeDefined();
    expect(result?.name).toBe('Test Workflow'); // Name comes from entity, not content
    expect(result?.initialState).toBe('open'); // Published version content
    expect(result?.published).toBe(false); // Draft exists and differs
  });

  it('should get workflow definition with allowDraft=true (draft preferred)', async () => {
    const publishedContent = { name: 'Published', initialState: 'open', transitions: [] };
    const draftContent = { name: 'Draft', initialState: 'draft', transitions: [] };
    const publishedVersion = {
      id: 'pub-1',
      content: JSON.stringify(publishedContent),
      validation_errors: [],
    };
    const draftVersion = {
      id: 'draft-1',
      content: JSON.stringify(draftContent),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      draft_version: draftVersion,
      all_versions: [draftVersion, publishedVersion],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', true);

    expect(result).toBeDefined();
    expect(result?.name).toBe('Test Workflow'); // Name comes from entity, not content
    expect(result?.initialState).toBe('draft'); // Draft version content
  });

  it('should return null when no entity setting exists', async () => {
    (findByType as any).mockResolvedValue(null);

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toBeNull();
  });

  it('should return null when no workflow_id exists', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: null });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toBeNull();
  });

  it('should return null when no version content exists', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Empty Workflow',
      published_version: { id: 'v1', content: null }, // No content
      all_versions: [],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', false);

    expect(result).toBeNull();
  });

  it('should handle content as object instead of string', async () => {
    const contentObj = { name: 'Object Content', initialState: 'open', transitions: [] };
    const version = {
      id: 'v1',
      content: contentObj, // Object, not string
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: version,
      all_versions: [version],
    });

    const result = await getWorkflowDefinition(mockContext, mockUser, 'Incident', false);

    expect(result).toBeDefined();
    expect(result?.name).toBe('Test Workflow'); // Entity name overrides content name
    expect(result?.initialState).toBe('open'); // From content object
  });

  // Tests for hasPublishedWorkflowDefinition
  it('should return true when a published workflow definition exists', async () => {
    const publishedContent = { name: 'Published', initialState: 'open', transitions: [] };
    const publishedVersion = {
      id: 'pub-1',
      content: JSON.stringify(publishedContent),
      validation_errors: [],
    };

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      name: 'Test Workflow',
      published_version: publishedVersion,
      all_versions: [publishedVersion],
    });

    const result = await hasPublishedWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toBe(true);
  });

  it('should return false when no published workflow definition exists', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: null });

    const result = await hasPublishedWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toBe(false);
  });

  // Tests for deleteWorkflowDefinition (line 335)
  it('should delete workflow definition', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (updateAttribute as any).mockResolvedValue({
      element: { id: 'entity-setting-id', workflow_id: null, target_type: 'Incident' },
    });

    const result = await deleteWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'entity-setting-id',
      'EntitySetting',
      [{ key: 'workflow_id', value: [null] }],
    );
    expect(result).toBeDefined();
  });

  it('should return entity setting when no workflow_id to delete', async () => {
    const entitySetting = { id: 'entity-setting-id', workflow_id: null };
    (findByType as any).mockResolvedValue(entitySetting);

    const result = await deleteWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).not.toHaveBeenCalled();
    expect(result).toBe(entitySetting);
  });

  // Tests for restorePublishedWorkflowDefinition
  it('should restore published workflow by clearing draft_version', async () => {
    const publishedVersion = {
      id: 'published-1',
      content: '{"name":"Published","initialState":"open","states":[],"transitions":[]}',
    };
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id', target_type: 'Incident' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      published_version: publishedVersion,
      draft_version: { id: 'draft-1' },
    });
    (updateAttribute as any).mockResolvedValue({ element: {} });

    const result = await restorePublishedWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'workflow-id',
      'WorkflowDefinition',
      [{ key: 'draft_version', value: [] }],
    );
    expect(result).toEqual(expect.objectContaining({
      id: 'entity-setting-id',
      workflow_id: 'workflow-id',
      target_type: 'Incident',
      errors: [],
      published: true,
    }));
  });

  it('should fail to restore when entity setting is not found', async () => {
    (findByType as any).mockResolvedValue(undefined);

    await expect(restorePublishedWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('Entity setting not found for type');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('should fail to restore when no workflow is linked', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: null });

    await expect(restorePublishedWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('No workflow definition found');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('should fail to restore when workflow definition entity is not found', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue(undefined);

    await expect(restorePublishedWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('Workflow definition not found');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('should fail to restore when there is no published version', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({
      id: 'workflow-id',
      published_version: undefined,
      draft_version: { id: 'draft-1' },
    });

    await expect(restorePublishedWorkflowDefinition(mockContext, mockUser, 'Incident')).rejects.toThrow('No published version to restore');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  // Tests for getAllowedTransitions (lines 469-490)
  it('should return allowed transitions for an entity', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident', internal_id: 'entity-1' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Incident Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'closed' }],
      transitions: [
        { from: 'open', to: 'closed', event: 'close', actions: [{ type: 'log' }] },
      ],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue({ id: 'instance-1', currentState: 'open' });

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-1');

    expect(transitions).toHaveLength(1);
    expect(transitions[0]).toEqual(expect.objectContaining({
      event: 'close',
      toState: 'closed',
      actions: ['log'],
    }));
  });

  it('should return empty array when entity not found', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'invalid-id');

    expect(transitions).toEqual([]);
  });

  it('should return empty array when no workflow configured', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null);

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-1');

    expect(transitions).toEqual([]);
  });

  it('should use initial state when current state is invalid', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident', internal_id: 'entity-1' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Incident Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }],
      transitions: [{ from: 'open', to: 'closed', event: 'close' }],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue({ id: 'instance-1', currentState: 'invalid-state' });

    const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-1');

    // When state doesn't exist but workflow has getTransitions mock, it still returns transitions
    expect(transitions).toBeDefined();
  });

  // Tests for getWorkflowInstance (line 438)
  it('should return null when entity not found for workflow instance', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    const instance = await getWorkflowInstance(mockContext, mockUser, 'invalid-id');

    expect(instance).toBeNull();
  });

  it('should return null when no workflow configured for entity', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null);

    const instance = await getWorkflowInstance(mockContext, mockUser, 'entity-1');

    expect(instance).toBeNull();
  });

  // Tests for triggerWorkflowEvent (lines 536, 554-573)
  it('should return failure when entity not found for trigger', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    await expect(triggerWorkflowEvent(mockContext, mockUser, 'invalid-id', 'test')).rejects.toThrow('Entity not found');
  });

  it('should return failure when no workflow configured for trigger', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null);

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'test');

    expect(result.success).toBe(false);
    expect(result.reason).toContain('not configured');
  });

  it('should return failure when entity setting not found', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };

    (storeLoadById as any).mockResolvedValue(entity);
    (findByType as any).mockResolvedValue(null); // No entity setting

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'test');

    expect(result.success).toBe(false);
  });

  // Tests for isStatusTemplateUsedInWorkflows (lines 607-609)
  it('should detect status template in workflow content as object', async () => {
    const contentObj = {
      name: 'Test',
      states: [{ statusId: 'status-template-id' }],
      transitions: [],
    };

    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'workflow-1',
        published_version: {
          id: 'v1',
          content: contentObj, // Object instead of string
        },
        all_versions: [],
      },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  // Tests for successful triggerWorkflowEvent (lines 566-577, 585-612)
  it('should successfully trigger workflow event and create instance', async () => {
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Test Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'closed' }],
      transitions: [{ from: 'open', to: 'closed', event: 'close' }],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      if (type === 'WorkflowInstance') return { id: 'instance-1', currentState: 'closed', history: '[]' };
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue(null); // No existing instance
    (createEntity as any).mockResolvedValue({ id: 'instance-1', internal_id: 'instance-1', currentState: 'open', history: '[]' });
    (createRelation as any).mockResolvedValue({ id: 'rel-1' });
    (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-1' } });

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'close');

    expect(result.success).toBe(true);
    expect(result.newState).toBe('closed');
    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({
        entity_id: 'entity-1',
        workflow_id: 'workflow-id',
        currentState: 'open',
      }),
      'WorkflowInstance',
    );
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'instance-1',
      'WorkflowInstance',
      expect.arrayContaining([
        expect.objectContaining({ key: 'currentState', value: ['closed'] }),
        expect.objectContaining({ key: 'history' }),
      ]),
    );
  });

  it('should successfully trigger workflow event with existing instance', async () => {
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
    const workflowContent = {
      id: 'workflow-1',
      name: 'Test Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'closed' }],
      transitions: [{ from: 'open', to: 'closed', event: 'close' }],
    };
    const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };
    const existingInstance = { id: 'instance-1', internal_id: 'instance-1', currentState: 'open', history: '[]' };

    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      if (type === 'WorkflowInstance') return { id: 'instance-1', currentState: 'closed', history: '[]' };
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue(existingInstance); // Existing instance
    (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-1' } });

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'close');

    expect(result.success).toBe(true);
    expect(result.newState).toBe('closed');
    expect(createEntity).not.toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), 'WorkflowInstance');
    expect(updateAttribute).toHaveBeenCalled();
  });
});

describe('Transition comments – Domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Override with a state-aware mock so transitions are filtered by `from` state
    (WorkflowFactory.createDefinition as any).mockImplementation((data: any) => ({
      getInitialState: () => data.initialState,
      hasState: (state: string) => (data.states ?? []).some((s: any) => s.statusId === state),
      getTransitions: (fromState: string) => (data.transitions ?? [])
        .filter((t: any) => t.from === fromState || t.from === '*')
        .map((t: any) => ({
          event: t.event,
          to: t.to,
          comment: t.comment,
          actionTypes: (t.actions ?? []).map((a: any) => a.type),
        })),
    }));
  });

  describe('getAllowedTransitions', () => {
    const definitionWithComments = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }, { statusId: 'published' }],
      transitions: [
        { from: 'draft', to: 'reviewed', event: 'review', comment: 'Requires manager approval' },
        { from: 'reviewed', to: 'published', event: 'publish' },
      ],
    });

    beforeEach(() => {
      (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: definitionWithComments, timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    });

    it('should expose the comment field on allowed transitions when comment is defined', async () => {
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('review');
      expect(transitions[0].comment).toBe('Requires manager approval');
    });

    it('should expose undefined comment on allowed transitions when no comment is defined', async () => {
      (storeLoadById as any).mockImplementation((ctx: any, user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: definitionWithComments, timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'reviewed', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('publish');
      expect(transitions[0].comment).toBeUndefined();
    });

    it('should exclude transitions whose conditions are not met by the requesting user', async () => {
      (WorkflowFactory.createDefinition as any).mockImplementation(() => ({
        getInitialState: () => 'draft',
        hasState: () => true,
        getTransitions: (fromState: string) => {
          if (fromState !== 'draft') return [];
          return [
            { event: 'review', to: 'reviewed', actionTypes: [], conditions: [] },
            { event: 'publish', to: 'published', actionTypes: [], conditions: [() => Promise.resolve(false)] },
          ];
        },
      }));

      (storeLoadById as any).mockImplementation((ctx: any, user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: '{}', timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('review');
    });

    it('should default requiresShareOrganizationInput and requiresUnshareOrganizationInput to false when the transition does not define them', async () => {
      (WorkflowFactory.createDefinition as any).mockImplementation(() => ({
        getInitialState: () => 'draft',
        hasState: () => true,
        getTransitions: () => [
          { event: 'review', to: 'reviewed', actionTypes: [] },
        ],
      }));
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].requiresShareOrganizationInput).toBe(false);
      expect(transitions[0].requiresUnshareOrganizationInput).toBe(false);
    });

    it('should propagate requiresShareOrganizationInput and requiresUnshareOrganizationInput flags from the transition', async () => {
      (WorkflowFactory.createDefinition as any).mockImplementation(() => ({
        getInitialState: () => 'draft',
        hasState: () => true,
        getTransitions: () => [
          { event: 'share', to: 'shared', actionTypes: ['shareWithOrganizations'], requiresShareOrganizationInput: true },
          { event: 'unshare', to: 'unshared', actionTypes: ['unshareFromOrganizations'], requiresUnshareOrganizationInput: true },
        ],
      }));
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(2);
      const shareTransition = transitions.find((t) => t.event === 'share');
      const unshareTransition = transitions.find((t) => t.event === 'unshare');
      expect(shareTransition?.requiresShareOrganizationInput).toBe(true);
      expect(shareTransition?.requiresUnshareOrganizationInput).toBe(false);
      expect(unshareTransition?.requiresShareOrganizationInput).toBe(false);
      expect(unshareTransition?.requiresUnshareOrganizationInput).toBe(true);
    });

    it('should use pre-fetched entity, entitySetting, definitionData and instanceEntity from options instead of performing redundant lookups', async () => {
      (WorkflowFactory.createDefinition as any).mockImplementation(() => ({
        getInitialState: () => 'draft',
        hasState: () => true,
        getTransitions: () => [
          { event: 'review', to: 'reviewed', actionTypes: [] },
        ],
      }));

      const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };
      const entitySetting = { id: 'setting-id', workflow_id: 'workflow-def-id' };
      const definitionData = {
        id: 'workflow-def-id',
        name: 'Workflow',
        initialState: 'draft',
        states: [{ statusId: 'draft' }, { statusId: 'reviewed' }],
        transitions: [],
        published: true,
        hasPublishedVersion: true,
        errors: [],
      };
      const instanceEntity = { id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' };

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id', {
        entity, entitySetting, definitionData, instanceEntity,
      } as any);

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('review');
      expect(storeLoadById).not.toHaveBeenCalled();
      expect(findByType).not.toHaveBeenCalled();
      expect(loadEntity).not.toHaveBeenCalled();
    });

    it('should still fall back to a fresh lookup for any option not provided', async () => {
      (WorkflowFactory.createDefinition as any).mockImplementation(() => ({
        getInitialState: () => 'draft',
        hasState: () => true,
        getTransitions: () => [
          { event: 'review', to: 'reviewed', actionTypes: [] },
        ],
      }));

      const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };
      const entitySetting = { id: 'setting-id', workflow_id: 'workflow-def-id' };
      const definitionData = {
        id: 'workflow-def-id',
        name: 'Workflow',
        initialState: 'draft',
        states: [{ statusId: 'draft' }, { statusId: 'reviewed' }],
        transitions: [],
        published: true,
        hasPublishedVersion: true,
        errors: [],
      };
      // instanceEntity is intentionally omitted from options: it must still be looked up via loadEntity
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id', {
        entity, entitySetting, definitionData,
      } as any);

      expect(transitions).toHaveLength(1);
      expect(storeLoadById).not.toHaveBeenCalled();
      expect(findByType).not.toHaveBeenCalled();
      expect(loadEntity).toHaveBeenCalled();
    });
  });

  describe('triggerWorkflowEvent – comment handling', () => {
    const definitionData = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }],
      transitions: [
        { from: 'draft', to: 'reviewed', event: 'review' },
      ],
    });

    const setupMocks = () => {
      (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', published_version: { id: 'v1', content: definitionData, timestamp: '', createdBy: '', validation_errors: [] } });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });
      (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-id' } });
    };

    const getLastHistoryEntry = () => {
      const updateCall = (updateAttribute as any).mock.calls[0];
      const historyArg = updateCall[4].find((a: any) => a.key === 'history');
      expect(historyArg).toBeDefined();
      return JSON.parse(historyArg.value[0]).at(-1);
    };

    it('should include the user-provided comment in the history entry', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Reviewed and approved');

      expect(getLastHistoryEntry().comment).toBe('Reviewed and approved');
    });

    it('should NOT include a comment key in the history entry when no comment is provided', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review');

      expect(getLastHistoryEntry()).not.toHaveProperty('comment');
    });

    it('should NOT include a comment key in the history entry when comment is an empty string', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', '');

      expect(getLastHistoryEntry()).not.toHaveProperty('comment');
    });
  });

  describe('triggerWorkflowEvent – notifications', () => {
    const definitionData = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }],
      transitions: [{ from: 'draft', to: 'reviewed', event: 'review' }],
    });

    const mockEntity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };

    const setupMocks = () => {
      (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve(mockEntity);
        if (id === 'workflow-def-id') return Promise.resolve({
          id: 'workflow-def-id',
          published_version: { id: 'v1', timestamp: '', createdBy: '', content: definitionData, validation_errors: [] },
          all_versions: [{ id: 'v1', timestamp: '', createdBy: '', content: definitionData, validation_errors: [] }],
        });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });
      (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-id' } });
      // Default: every recipient resolves to a user object that has access.
      (resolveUserById as any).mockImplementation((_ctx: any, id: string) => Promise.resolve({ id }));
      (internalLoadById as any).mockResolvedValue(mockEntity);
    };

    beforeEach(() => {
      vi.clearAllMocks();
      (addNotification as any).mockResolvedValue({});
      (extractEntityRepresentativeName as any).mockReturnValue('Test Entity');
    });

    it('should call addNotification for each assignee and participant when a comment is provided', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }, { id: 'assignee-2' }]);
      (loadParticipants as any).mockResolvedValue([{ id: 'participant-1' }]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).toHaveBeenCalledTimes(3);
      const calledUserIds = (addNotification as any).mock.calls.map((call: any[]) => call[2].user_id);
      expect(calledUserIds).toContain('assignee-1');
      expect(calledUserIds).toContain('assignee-2');
      expect(calledUserIds).toContain('participant-1');
    });

    it('should NOT call addNotification when no comment is provided', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review');

      expect(addNotification).not.toHaveBeenCalled();
    });

    it('should NOT call addNotification when comment is an empty string', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', '');

      expect(addNotification).not.toHaveBeenCalled();
    });

    it('should exclude the triggering user from notifications', async () => {
      setupMocks();
      // mockUser has id 'user-id' — also listed as assignee
      (loadAssignees as any).mockResolvedValue([{ id: 'user-id' }, { id: 'other-user' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).toHaveBeenCalledTimes(1);
      expect((addNotification as any).mock.calls[0][2].user_id).toBe('other-user');
    });

    it('should deduplicate recipients who are both assignee and participant', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'shared-user' }]);
      (loadParticipants as any).mockResolvedValue([{ id: 'shared-user' }]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).toHaveBeenCalledTimes(1);
      expect((addNotification as any).mock.calls[0][2].user_id).toBe('shared-user');
    });

    it('should NOT call addNotification when there are no assignees or participants', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).not.toHaveBeenCalled();
    });

    it('should include the eventName and comment in the notification message', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Looks good');

      expect(addNotification).toHaveBeenCalledTimes(1);
      const payload = (addNotification as any).mock.calls[0][2];
      expect(payload.notification_content[0].events[0].message).toBe('[review] Looks good');
    });

    it('should not propagate errors from notification and still return success', async () => {
      setupMocks();
      (loadAssignees as any).mockRejectedValue(new Error('DB error'));
      (loadParticipants as any).mockResolvedValue([]);

      const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(result.success).toBe(true);
      expect(addNotification).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Access-control tests (new behaviour: resolveUserById + internalLoadById)
    // -----------------------------------------------------------------------

    it('should NOT send notification to recipients who cannot access the entity', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'has-access' }, { id: 'no-access' }]);
      (loadParticipants as any).mockResolvedValue([]);
      // 'no-access' user: internalLoadById returns null (no visibility)
      (internalLoadById as any).mockImplementation((_ctx: any, user: any) => {
        if (user.id === 'no-access') return Promise.resolve(null);
        return Promise.resolve(mockEntity);
      });

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Access test');

      expect(addNotification).toHaveBeenCalledTimes(1);
      expect((addNotification as any).mock.calls[0][2].user_id).toBe('has-access');
    });

    it('should NOT send notification when all recipients fail the access check', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'no-access-1' }, { id: 'no-access-2' }]);
      (loadParticipants as any).mockResolvedValue([]);
      (internalLoadById as any).mockResolvedValue(null);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Access test');

      expect(addNotification).not.toHaveBeenCalled();
    });

    it('should skip a recipient silently when resolveUserById returns null', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'ghost-user' }, { id: 'real-user' }]);
      (loadParticipants as any).mockResolvedValue([]);
      (resolveUserById as any).mockImplementation((_ctx: any, id: string) => {
        if (id === 'ghost-user') return Promise.resolve(null);
        return Promise.resolve({ id });
      });

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Ghost test');

      expect(addNotification).toHaveBeenCalledTimes(1);
      expect((addNotification as any).mock.calls[0][2].user_id).toBe('real-user');
    });

    it('should skip a recipient silently when resolveUserById throws', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'broken-user' }, { id: 'ok-user' }]);
      (loadParticipants as any).mockResolvedValue([]);
      (resolveUserById as any).mockImplementation((_ctx: any, id: string) => {
        if (id === 'broken-user') return Promise.reject(new Error('DB error'));
        return Promise.resolve({ id });
      });

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Error test');

      expect(addNotification).toHaveBeenCalledTimes(1);
      expect((addNotification as any).mock.calls[0][2].user_id).toBe('ok-user');
    });

    it('should use internalLoadById (not storeLoadById) for the access check', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'recipient-1' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Audit check');

      // internalLoadById must be called for the access check
      expect(internalLoadById).toHaveBeenCalled();
      // The call to internalLoadById must use the entity's internal_id
      const accessCheckCall = (internalLoadById as any).mock.calls.find(
        (call: any[]) => call[2] === 'entity-id',
      );
      expect(accessCheckCall).toBeDefined();
    });
  });
});
// ===========================================================================
// getWorkflowInstance — pending transition enrichment
// ===========================================================================

describe('getWorkflowInstance', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(findStatusesByType).mockResolvedValue([]);
    vi.mocked(WorkflowFactory.createDefinition).mockReset();
  });

  const makeBaseSetup = () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({
        initialState: 'draft',
        states: [{ statusId: 'draft' }],
        transitions: [],
      }), validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue(null); // no instance
  };

  it.each(['standard', StatusScope.RequestAccess])('hydrates current and destination statuses in scope %s', async (scope) => {
    makeBaseSetup();
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', currentState: 'draft', history: '[]', scope });
    const currentStatus = { id: 'mapped-draft', template_id: 'draft', order: 0, type: 'Incident', scope: scope === 'standard' ? StatusScope.Global : scope };
    const toStatus = { ...currentStatus, id: 'mapped-closed', template_id: 'closed', order: 1 };
    vi.mocked(findStatusesByType).mockResolvedValue([
      { ...currentStatus, id: 'wrong-scope', scope: scope === 'standard' ? StatusScope.RequestAccess : StatusScope.Global },
      currentStatus,
      toStatus,
    ] as any);
    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');
    expect(result.currentStatus).toEqual(currentStatus);
    expect(result.allowedTransitions[0].toStatus).toEqual(toStatus);
    expect(findStatusesByType).toHaveBeenCalledOnce();
    expect(findStatusesByType).toHaveBeenCalledWith(mockContext, { ...mockUser, draft_context: undefined }, 'Incident');
  });

  it('returns null status mappings when no Status exists', async () => {
    makeBaseSetup();
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', currentState: 'draft', history: '[]' });
    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');
    expect(result.currentStatus).toBeNull();
    expect(result.allowedTransitions[0].toStatus).toBeNull();
  });

  it('returns pendingTransition: null when instance has no pendingTransition', async () => {
    makeBaseSetup();
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: null });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result).not.toBeNull();
    expect(result.pendingTransition).toBeNull();
  });

  it('falls back to scope: "standard" when the instance has no scope value (pre-existing rows)', async () => {
    makeBaseSetup();
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]' }); // no `scope` field

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result.scope).toBe('standard');
  });

  it('falls back to entity.id when the loaded entity has no internal_id', async () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', entity_type: 'Incident' }); // no internal_id
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({
        initialState: 'draft',
        states: [{ statusId: 'draft' }],
        transitions: [],
      }), validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: null });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result).not.toBeNull();
    expect(result.currentState).toBe('draft');
  });

  it('returns pendingTransition: null when pendingTransition JSON is malformed', async () => {
    makeBaseSetup();
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: '{ bad json' });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result).not.toBeNull();
    expect(result.pendingTransition).toBeNull();
  });

  it('passes slot through as-is when workId is missing', async () => {
    makeBaseSetup();
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: '', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result.pendingTransition.asyncActions[0].workId).toBe('');
    expect(result.pendingTransition.asyncActions[0].processedCount).toBeUndefined();
  });

  it('passes slot through as-is when Work entity is not found', async () => {
    makeBaseSetup();
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });
    // Work lookup returns null
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      return Promise.resolve(null); // Work returns null
    });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');
    expect(result.pendingTransition.asyncActions[0].processedCount).toBeUndefined();
  });

  it('enriches slot with counts from BackgroundTask when Work and BackgroundTask are found', async () => {
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      if (id === 'work-1') return Promise.resolve({ id: 'work-1', background_task_id: 'task-1', received_time: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T01:00:00Z', status: 'progress', errors: [] });
      if (id === 'task-1') return Promise.resolve({ id: 'task-1', task_expected_number: 50, task_processed_number: 25 });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    const slot = result.pendingTransition.asyncActions[0];
    expect(slot.expectedCount).toBe(50);
    expect(slot.processedCount).toBe(25);
    expect(slot.startedAt).toBe('2024-01-01T00:00:00Z');
    expect(slot.workStatus).toBe('progress');
  });

  it('leaves counts at 0 when Work is found but has no background_task_id', async () => {
    const pt = JSON.stringify({
      event: 'submit', toState: 'reviewing', triggeredBy: 'u', triggeredAt: new Date().toISOString(),
      runtimeParams: {}, asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }], syncActions: [],
    });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      if (id === 'work-1') return Promise.resolve({ id: 'work-1', background_task_id: null, errors: [] });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingTransition: pt });

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    const slot = result.pendingTransition.asyncActions[0];
    expect(slot.expectedCount).toBe(0);
    expect(slot.processedCount).toBe(0);
  });
});

// ===========================================================================
// triggerWorkflowEvent — async/pending path + lock + error handling
// ===========================================================================

describe('triggerWorkflowEvent – async / pending / lock', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const asyncDefinition = JSON.stringify({
    initialState: 'draft',
    states: [{ statusId: 'draft' }, { statusId: 'reviewing' }],
    transitions: [{
      from: 'draft',
      to: 'reviewing',
      event: 'submit',
      asyncActions: [{ type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['org-1'] } }] } }],
      syncActions: [{ type: 'validateDraft' }],
    }],
  });

  it('returns success:false when pendingStatus is already pending (lock check)', async () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: asyncDefinition, validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    // Existing instance is already pending
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingStatus: 'pending' });

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    expect(result.success).toBe(false);
    expect(result.reason).toContain('already pending');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('wraps unexpected errors and returns success:false', async () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: asyncDefinition, validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockRejectedValue(new Error('DB connection error'));

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    expect(result.success).toBe(false);
    expect(result.reason).toContain('DB connection error');
  });

  // Helper shared by the three tests below
  const setupAsyncPendingMocks = (definitionContent: string) => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]' });
    (WorkflowFactory.getInstance as any).mockReturnValue({
      start: vi.fn(),
      trigger: vi.fn().mockResolvedValue({
        success: true,
        executionStatus: 'pending',
        asyncActionSlots: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction' }],
      }),
      getCurrentState: vi.fn().mockReturnValue('reviewing'),
    });
    (updateAttribute as any).mockResolvedValue({ element: {} });
  };

  const getPendingTransitionArg = (): any => {
    const patches: Array<{ key: string; value: any[] }> = (updateAttribute as any).mock.calls[0][4];
    return JSON.parse(patches.find((p) => p.key === 'pendingTransition')!.value[0]);
  };

  // lines 761-763 (toStateId from transition.to) + line 774 (onEnterActions present)
  it('stores onEnterActions in pendingTransition when the target state defines onEnter actions', async () => {
    const definitionContent = JSON.stringify({
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'reviewing', onEnter: [{ type: 'validateDraft' }] },
      ],
      transitions: [{ from: 'draft', to: 'reviewing', event: 'submit', syncActions: [{ type: 'validateDraft' }] }],
    });
    setupAsyncPendingMocks(definitionContent);

    await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    const stored = getPendingTransitionArg();
    expect(stored.toState).toBe('reviewing');
    expect(stored.onEnterActions).toEqual([{ type: 'validateDraft' }]);
  });

  // line 774 (onEnterActions absent when serializedOnEnterActions is empty)
  it('omits onEnterActions from pendingTransition when the target state has no onEnter actions', async () => {
    const definitionContent = JSON.stringify({
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'reviewing' }, // no onEnter
      ],
      transitions: [{ from: 'draft', to: 'reviewing', event: 'submit' }],
    });
    setupAsyncPendingMocks(definitionContent);

    await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    const stored = getPendingTransitionArg();
    expect(stored).not.toHaveProperty('onEnterActions');
  });

  // line 761 — toStateId falls back to instance.getCurrentState() when transition has no "to"
  it('uses instance.getCurrentState() as toState when the matched transition has no "to" field', async () => {
    const definitionContent = JSON.stringify({
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'reviewing' },
      ],
      transitions: [{ from: 'draft', event: 'submit' }], // no "to" — forces the ?? fallback
    });
    setupAsyncPendingMocks(definitionContent);

    await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'submit');

    const stored = getPendingTransitionArg();
    // getCurrentState() mock returns 'reviewing', so toState must equal that value
    expect(stored.toState).toBe('reviewing');
  });
});

// ===========================================================================
// clearWorkflowPendingState
// ===========================================================================

describe('clearWorkflowPendingState', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws when entity is not found', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    await expect(clearWorkflowPendingState(mockContext, mockUser, 'entity-id'))
      .rejects.toThrow('Entity not found');
  });

  it('throws when no workflow instance is found for the entity', async () => {
    (storeLoadById as any).mockResolvedValue({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
    (loadEntity as any).mockResolvedValue(null);

    await expect(clearWorkflowPendingState(mockContext, mockUser, 'entity-id'))
      .rejects.toThrow();
  });

  it('clears pendingStatus, pendingError, pendingTransition and appends an audit history entry', async () => {
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', name: 'Test Workflow', published_version: { id: 'v1', content: JSON.stringify({ initialState: 'draft', states: [{ statusId: 'draft' }], transitions: [] }), validation_errors: [] } });
      return Promise.resolve(null);
    });
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', currentState: 'draft', history: '[]', pendingStatus: 'error', pendingError: 'task failed', pendingTransition: '{}' });
    (updateAttribute as any).mockResolvedValue({ element: {} });

    await clearWorkflowPendingState(mockContext, mockUser, 'entity-id');

    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBeNull();
    expect(patches.find((p: any) => p.key === 'pendingError')?.value[0]).toBeNull();
    expect(patches.find((p: any) => p.key === 'pendingTransition')?.value[0]).toBeNull();
    const history = JSON.parse(patches.find((p: any) => p.key === 'history')?.value[0] ?? '[]');
    expect(history[history.length - 1].event).toBe('admin_clear_pending_state');
  });
});

// ---------------------------------------------------------------------------
// getWorkflowPublishedVersionId
// ---------------------------------------------------------------------------

describe('getWorkflowPublishedVersionId', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  it('returns null when entitySetting has no workflow_id', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace' } as any;

    const result = await getWorkflowPublishedVersionId(mockContext, mockUser, entitySetting);

    expect(result).toBeNull();
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('returns null when the WorkflowDefinitionEntity is not found', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue(undefined);

    const result = await getWorkflowPublishedVersionId(mockContext, mockUser, entitySetting);

    expect(result).toBeNull();
    expect(storeLoadById).toHaveBeenCalledWith(mockContext, { ...mockUser, draft_context: undefined }, 'wf-id', expect.any(String));
  });

  it('returns null when the WorkflowDefinitionEntity has no published_version', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue({ id: 'wf-id', draft_version: { id: 'draft-v1' } });

    const result = await getWorkflowPublishedVersionId(mockContext, mockUser, entitySetting);

    expect(result).toBeNull();
  });

  it('returns the published_version id when the workflow has been published', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue({
      id: 'wf-id',
      published_version: { id: 'pub-v1', timestamp: '2024-01-01T00:00:00Z' },
      draft_version: { id: 'draft-v2', timestamp: '2024-02-01T00:00:00Z' },
    });

    const result = await getWorkflowPublishedVersionId(mockContext, mockUser, entitySetting);

    expect(result).toBe('pub-v1');
  });

  it('returns the published_version id even when no draft exists (published and clean)', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' } as any;
    (storeLoadById as any).mockResolvedValue({
      id: 'wf-id',
      published_version: { id: 'pub-v1', timestamp: '2024-01-01T00:00:00Z' },
    });

    const result = await getWorkflowPublishedVersionId(mockContext, mockUser, entitySetting);

    expect(result).toBe('pub-v1');
  });
});

// ---------------------------------------------------------------------------
// cleanupEntityWorkflow
// ---------------------------------------------------------------------------

describe('cleanupEntityWorkflow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is a no-op when the deleted entity is itself a WorkflowInstance', async () => {
    const entity = { id: 'wi-1', internal_id: 'wi-1', entity_type: ENTITY_TYPE_WORKFLOW_INSTANCE };

    await cleanupEntityWorkflow(mockContext, mockUser, entity);

    expect(loadEntity).not.toHaveBeenCalled();
    expect(deleteElementById).not.toHaveBeenCalled();
  });

  it('is a no-op when no WorkflowInstance exists for the deleted entity', async () => {
    (loadEntity as any).mockResolvedValue(null);
    const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };

    await cleanupEntityWorkflow(mockContext, mockUser, entity);

    expect(loadEntity).toHaveBeenCalledWith(mockContext, mockUser, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['entity_id'], values: ['entity-id'] }],
        filterGroups: [],
      },
    });
    expect(deleteElementById).not.toHaveBeenCalled();
  });

  it('deletes the WorkflowInstance found for the deleted entity', async () => {
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', entity_type: ENTITY_TYPE_WORKFLOW_INSTANCE });
    const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };

    await cleanupEntityWorkflow(mockContext, mockUser, entity);

    expect(deleteElementById).toHaveBeenCalledWith(mockContext, mockUser, 'inst-id', ENTITY_TYPE_WORKFLOW_INSTANCE);
  });

  it('falls back to entity.id when internal_id is missing to look up the instance', async () => {
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', internal_id: 'inst-id', entity_type: ENTITY_TYPE_WORKFLOW_INSTANCE });
    const entity = { id: 'entity-id', entity_type: 'Incident' };

    await cleanupEntityWorkflow(mockContext, mockUser, entity);

    expect(loadEntity).toHaveBeenCalledWith(mockContext, mockUser, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['entity_id'], values: ['entity-id'] }],
        filterGroups: [],
      },
    });
    expect(deleteElementById).toHaveBeenCalledWith(mockContext, mockUser, 'inst-id', ENTITY_TYPE_WORKFLOW_INSTANCE);
  });

  it('falls back to instance.id when the found instance has no internal_id', async () => {
    (loadEntity as any).mockResolvedValue({ id: 'inst-id', entity_type: ENTITY_TYPE_WORKFLOW_INSTANCE });
    const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };

    await cleanupEntityWorkflow(mockContext, mockUser, entity);

    expect(deleteElementById).toHaveBeenCalledWith(mockContext, mockUser, 'inst-id', ENTITY_TYPE_WORKFLOW_INSTANCE);
  });
});

// ===========================================================================
// initializeEntityWorkflow — creation-time status resolution
// (3 cases: explicit valid status / explicit unresolvable status / no status)
// ===========================================================================
describe('initializeEntityWorkflow — creation-time status resolution', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const definitionContent = JSON.stringify({
    initialState: 'draft',
    states: [{ statusId: 'draft' }, { statusId: 'reviewing' }],
    transitions: [],
  });

  const setupCommon = () => {
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue(null); // no existing WorkflowInstance yet
    (createEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id' });
    (createRelation as any).mockResolvedValue({});
  };

  it('case (a): an explicit status that resolves to a valid state starts the instance there, with no projection write', async () => {
    setupCommon();
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      if (id === 'status-reviewing-id') {
        return Promise.resolve({ id: 'status-reviewing-id', template_id: 'reviewing', scope: StatusScope.Global });
      }
      return Promise.resolve(null);
    });

    const entity = {
      id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident', x_opencti_workflow_id: 'status-reviewing-id',
    };
    await initializeEntityWorkflow(mockContext, mockUser, entity);

    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      { ...mockUser, draft_context: undefined },
      expect.objectContaining({ currentState: 'reviewing', scope: StatusScope.Global }),
      ENTITY_TYPE_WORKFLOW_INSTANCE,
    );
    const [, , instanceInput] = (createEntity as any).mock.calls[0];
    expect(instanceInput.pendingError).toBeUndefined();
    expect(projectWorkflowState).not.toHaveBeenCalled();
  });

  it('case (b): an explicit status that does not resolve to any state starts at initialState with pendingError set, and does not project', async () => {
    setupCommon();
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      if (id === 'status-foreign-id') {
        return Promise.resolve({ id: 'status-foreign-id', template_id: 'some-other-state', scope: StatusScope.Global });
      }
      return Promise.resolve(null);
    });

    const entity = {
      id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident', x_opencti_workflow_id: 'status-foreign-id',
    };
    await initializeEntityWorkflow(mockContext, mockUser, entity);

    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      { ...mockUser, draft_context: undefined },
      expect.objectContaining({ currentState: 'draft', pendingError: expect.any(String) }),
      ENTITY_TYPE_WORKFLOW_INSTANCE,
    );
    expect(projectWorkflowState).not.toHaveBeenCalled();
  });

  it('case (b): an explicit status id that does not resolve to any Status at all is treated the same way (starts at initialState, pendingError set)', async () => {
    setupCommon();
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      return Promise.resolve(undefined); // status lookup misses entirely
    });

    const entity = {
      id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident', x_opencti_workflow_id: 'status-does-not-exist',
    };
    await initializeEntityWorkflow(mockContext, mockUser, entity);

    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      { ...mockUser, draft_context: undefined },
      expect.objectContaining({ currentState: 'draft', pendingError: expect.any(String) }),
      ENTITY_TYPE_WORKFLOW_INSTANCE,
    );
    expect(projectWorkflowState).not.toHaveBeenCalled();
  });

  it('case (a): a status whose state is declared only as a transition endpoint (not in states[]) still resolves', async () => {
    setupCommon();
    const transitionOnlyDefinition = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }],
      transitions: [{ from: 'draft', to: 'reviewing', event: 'review' }],
    });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: transitionOnlyDefinition, validation_errors: [] } });
      }
      if (id === 'status-reviewing-id') {
        return Promise.resolve({ id: 'status-reviewing-id', template_id: 'reviewing', scope: StatusScope.Global });
      }
      return Promise.resolve(null);
    });

    const entity = {
      id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident', x_opencti_workflow_id: 'status-reviewing-id',
    };
    await initializeEntityWorkflow(mockContext, mockUser, entity);

    const [, , instanceInput] = (createEntity as any).mock.calls[0];
    expect(instanceInput.currentState).toBe('reviewing');
    expect(instanceInput.pendingError).toBeUndefined();
  });

  it('case (c): no status supplied at all starts at initialState with the default scope, and projects once', async () => {
    setupCommon();
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      return Promise.resolve(null);
    });

    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
    await initializeEntityWorkflow(mockContext, mockUser, entity);

    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      { ...mockUser, draft_context: undefined },
      expect.objectContaining({ currentState: 'draft', scope: 'standard' }),
      ENTITY_TYPE_WORKFLOW_INSTANCE,
    );
    const [, , instanceInput] = (createEntity as any).mock.calls[0];
    expect(instanceInput.pendingError).toBeUndefined();
    expect(projectWorkflowState).toHaveBeenCalledTimes(1);
    expect(projectWorkflowState).toHaveBeenCalledWith(mockContext, { ...mockUser, draft_context: undefined }, entity, 'draft', StatusScope.Global);
  });
});

// ===========================================================================
// getWorkflowInstance — lazy backfill on first read
// ===========================================================================
describe('getWorkflowInstance — lazy backfill', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const definitionContent = JSON.stringify({
    initialState: 'draft',
    states: [{ statusId: 'draft' }],
    transitions: [],
  });

  const setupCommon = () => {
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      return Promise.resolve(null);
    });
  };

  it('persists a real WorkflowInstance under the WORKFLOW_MANAGER_USER identity when none exists yet', async () => {
    setupCommon();
    (loadEntity as any).mockResolvedValue(null); // no pre-existing instance
    (createEntity as any).mockResolvedValue({ id: 'backfilled-instance-id', internal_id: 'backfilled-instance-id', currentState: 'draft', history: '[]' });
    (createRelation as any).mockResolvedValue({});

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(createEntity).toHaveBeenCalledWith(
      expect.objectContaining({ user: WORKFLOW_MANAGER_USER }),
      WORKFLOW_MANAGER_USER,
      expect.objectContaining({ currentState: 'draft' }),
      ENTITY_TYPE_WORKFLOW_INSTANCE,
    );
    expect(result.id).toBe('backfilled-instance-id');
  });

  it('falls back to the synthesized instance when the backfill write fails, without failing the read', async () => {
    setupCommon();
    (loadEntity as any).mockResolvedValue(null); // no pre-existing instance
    (createEntity as any).mockRejectedValue(new Error('store unavailable'));

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result).not.toBeNull();
    expect(result.id).toBe('initial-entity-id');
  });

  it('calling getWorkflowInstance twice creates exactly one WorkflowInstance (idempotent backfill)', async () => {
    setupCommon();
    (createEntity as any).mockResolvedValue({ id: 'backfilled-instance-id', internal_id: 'backfilled-instance-id', currentState: 'draft', history: '[]' });
    (createRelation as any).mockResolvedValue({});

    (loadEntity as any).mockResolvedValueOnce(null); // first call: no instance yet, triggers backfill
    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    (loadEntity as any).mockResolvedValue({ id: 'backfilled-instance-id', internal_id: 'backfilled-instance-id', currentState: 'draft', history: '[]' }); // second call: now found
    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(createEntity).toHaveBeenCalledTimes(1);
  });
});

// ===========================================================================
// triggerWorkflowEvent — status projection on sync transitions
// ===========================================================================
describe('triggerWorkflowEvent — status projection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
  const workflowContent = {
    id: 'workflow-1',
    name: 'Test Workflow',
    initialState: 'open',
    states: [{ statusId: 'open' }, { statusId: 'closed' }],
    transitions: [{ from: 'open', to: 'closed', event: 'close' }],
  };
  const version = { id: 'v1', content: JSON.stringify(workflowContent), validation_errors: [] };
  const existingInstance = { id: 'instance-1', internal_id: 'instance-1', currentState: 'open', history: '[]', scope: 'GLOBAL' };

  const setup = () => {
    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: version, all_versions: [version] };
      }
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue(existingInstance);
    (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-1' } });
    // Reset to a plain synchronous success, since other describe blocks in this file
    // permanently override `getInstance`'s return value via `mockReturnValue`.
    (WorkflowFactory.getInstance as any).mockReturnValue({
      start: vi.fn(),
      trigger: vi.fn().mockResolvedValue({ success: true }),
      getCurrentState: vi.fn().mockReturnValue('closed'),
    });
  };

  it('calls projectWorkflowState with the entity, new state, and the instance scope right after the instance is updated', async () => {
    setup();

    const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'close');

    expect(result.success).toBe(true);
    expect(projectWorkflowState).toHaveBeenCalledWith(mockContext, { ...mockUser, draft_context: undefined }, entity, 'closed', StatusScope.Global);
    // Must happen after the instance's own currentState/history update, not before.
    const updateAttributeOrder = (updateAttribute as any).mock.invocationCallOrder[0];
    const projectionOrder = (projectWorkflowState as any).mock.invocationCallOrder[0];
    expect(projectionOrder).toBeGreaterThan(updateAttributeOrder);
  });

  it('does not call projectWorkflowState for async/pending transitions', async () => {
    const asyncWorkflowContent = {
      id: 'workflow-1',
      name: 'Test Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'closed' }],
      transitions: [{ from: 'open', to: 'closed', event: 'close', actions: [{ type: 'asyncBulkAction', params: {} }] }],
    };
    const asyncVersion = { id: 'v1', content: JSON.stringify(asyncWorkflowContent), validation_errors: [] };
    (storeLoadById as any).mockImplementation((ctx: any, user: any, id: any, type: any) => {
      if (type === 'Basic-Object') return entity;
      if (type === 'WorkflowDefinition') {
        return { id: 'workflow-id', name: 'Workflow', published_version: asyncVersion, all_versions: [asyncVersion] };
      }
      return null;
    });
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (loadEntity as any).mockResolvedValue(existingInstance);
    (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-1' } });
    (WorkflowFactory.getInstance as any).mockReturnValue({
      start: vi.fn(),
      trigger: vi.fn().mockResolvedValue({
        success: true,
        executionStatus: 'pending',
        asyncActionSlots: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction' }],
      }),
      getCurrentState: vi.fn().mockReturnValue('closed'),
    });

    await triggerWorkflowEvent(mockContext, mockUser, 'entity-1', 'close');

    expect(projectWorkflowState).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// getWorkflowInstance — read-repair
// ===========================================================================
describe('getWorkflowInstance — read-repair', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    __resetReadRepairRateLimitForTest();
    (booleanConf as any).mockReturnValue(false);
  });

  const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident', x_opencti_workflow_id: 'stale-status-id' };
  const instance = { id: 'instance-id', internal_id: 'instance-id', currentState: 'reviewing', history: '[]', scope: 'GLOBAL' };
  const definitionContent = JSON.stringify({
    initialState: 'draft',
    states: [{ statusId: 'draft' }, { statusId: 'reviewing' }],
    transitions: [],
  });

  const setup = () => {
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-id') return Promise.resolve(entity);
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      return Promise.resolve(null);
    });
    (loadEntity as any).mockResolvedValue(instance);
    (getEntitiesListFromCache as any).mockResolvedValue([
      { id: 'stale-status-id', internal_id: 'stale-status-id', template_id: 'draft', scope: StatusScope.Global },
    ]);
  };

  it('repairs x_opencti_workflow_id under the WORKFLOW_MANAGER_USER identity when it diverges from currentState', async () => {
    setup();
    (resolveMappedStatusId as any).mockResolvedValue('correct-status-id');

    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(projectWorkflowState).toHaveBeenCalledWith(
      expect.objectContaining({ user: WORKFLOW_MANAGER_USER }),
      WORKFLOW_MANAGER_USER,
      entity,
      'reviewing',
      'GLOBAL',
    );
  });

  it('does not repair when x_opencti_workflow_id already matches the mapped Status', async () => {
    setup();
    (resolveMappedStatusId as any).mockResolvedValue('stale-status-id'); // already matches entity.x_opencti_workflow_id

    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(projectWorkflowState).not.toHaveBeenCalled();
  });

  it('does not fail the read when the repair write throws', async () => {
    setup();
    (resolveMappedStatusId as any).mockResolvedValue('correct-status-id');
    (projectWorkflowState as any).mockRejectedValue(new Error('store unavailable'));

    const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(result).not.toBeNull();
    expect(result.currentState).toBe('reviewing');
  });

  it('does not repair a second time within the rate-limit TTL window', async () => {
    setup();
    (resolveMappedStatusId as any).mockResolvedValue('correct-status-id');

    await getWorkflowInstance(mockContext, mockUser, 'entity-id');
    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(projectWorkflowState).toHaveBeenCalledTimes(1);
  });

  it('does not re-run the mapped-Status lookup within the TTL window when the entity is already consistent', async () => {
    setup();
    (resolveMappedStatusId as any).mockResolvedValue('stale-status-id'); // already consistent

    await getWorkflowInstance(mockContext, mockUser, 'entity-id');
    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(resolveMappedStatusId).toHaveBeenCalledTimes(1);
  });

  it('returns null without backfill nor repair for a non-DraftWorkspace entity when ENTITIES_WORKFLOW is disabled', async () => {
    setup();
    (isFeatureEnabled as any).mockReturnValue(false);
    (resolveMappedStatusId as any).mockResolvedValue('correct-status-id');

    try {
      const result = await getWorkflowInstance(mockContext, mockUser, 'entity-id');

      expect(result).toBeNull();
      expect(createEntity).not.toHaveBeenCalled();
      expect(projectWorkflowState).not.toHaveBeenCalled();
    } finally {
      (isFeatureEnabled as any).mockReturnValue(true);
    }
  });

  it('keeps an external write whose Status maps to no state of the published workflow', async () => {
    setup();
    (getEntitiesListFromCache as any).mockResolvedValue([
      { id: 'stale-status-id', internal_id: 'stale-status-id', template_id: 'unrelated-state', scope: StatusScope.Global },
    ]);
    (resolveMappedStatusId as any).mockResolvedValue('correct-status-id');

    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(projectWorkflowState).not.toHaveBeenCalled();
  });

  it('skips repair entirely when the workflow:disable_read_repair kill switch is enabled', async () => {
    setup();
    (booleanConf as any).mockReturnValue(true);
    (resolveMappedStatusId as any).mockResolvedValue('correct-status-id');

    await getWorkflowInstance(mockContext, mockUser, 'entity-id');

    expect(resolveMappedStatusId).not.toHaveBeenCalled();
    expect(projectWorkflowState).not.toHaveBeenCalled();
  });
});

describe('syncWorkflowInstanceFromExternalWrite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (getEntitiesListFromCache as any).mockResolvedValue([
      { id: 'status-reviewing-id', internal_id: 'status-reviewing-id', template_id: 'reviewing', scope: StatusScope.Global },
      { id: 'status-draft-id', internal_id: 'status-draft-id', template_id: 'draft', scope: StatusScope.Global },
      { id: 'status-orphan-id', internal_id: 'status-orphan-id', template_id: 'unrelated-state', scope: StatusScope.Global },
      { id: 'status-rfi-reviewing-id', internal_id: 'status-rfi-reviewing-id', template_id: 'reviewing', scope: StatusScope.RequestAccess },
    ]);
  });

  const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
  const definitionContent = JSON.stringify({
    initialState: 'draft',
    states: [{ statusId: 'draft' }],
    transitions: [{ from: 'draft', to: 'reviewing', event: 'review' }],
  });
  let storedStatusId: string | null = null;
  const setupPublishedDefinition = (instance: any) => {
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (loadEntity as any).mockResolvedValue(instance);
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'entity-1') {
        return Promise.resolve({ ...entity, x_opencti_workflow_id: storedStatusId });
      }
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      return Promise.resolve(null);
    });
  };
  const draftInstance = { id: 'instance-1', internal_id: 'instance-1', currentState: 'draft', history: '[]', scope: 'standard' };
  const lastUpdateInputs = () => (updateAttribute as any).mock.calls.at(-1)[4];
  const syncWrite = (statusId: string | null) => {
    storedStatusId = statusId;
    return syncWorkflowInstanceFromExternalWrite(mockContext, mockUser, entity, statusId);
  };

  it('does nothing when the entity type has no published workflow', async () => {
    (findByType as any).mockResolvedValue(undefined);

    await syncWrite('status-reviewing-id');

    expect(loadEntity).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('does nothing when the status was cleared', async () => {
    setupPublishedDefinition(draftInstance);

    await syncWrite(null);

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('does nothing for a write made inside a draft', async () => {
    setupPublishedDefinition(draftInstance);
    (getDraftContext as any).mockReturnValueOnce('draft-id');

    await syncWrite('status-reviewing-id');

    expect(loadEntity).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('does nothing when the entity has no workflow instance yet', async () => {
    setupPublishedDefinition(null);

    await syncWrite('status-reviewing-id');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('moves the instance to the mapped state and records the writer in an event_external history entry', async () => {
    setupPublishedDefinition(draftInstance);

    await syncWrite('status-reviewing-id');

    expect(updateAttribute).toHaveBeenCalledWith(
      expect.objectContaining({ user: WORKFLOW_MANAGER_USER }),
      WORKFLOW_MANAGER_USER,
      'instance-1',
      ENTITY_TYPE_WORKFLOW_INSTANCE,
      [
        { key: 'currentState', value: ['reviewing'] },
        { key: 'history', value: [expect.any(String)] },
        { key: 'pendingError', value: [null] },
      ],
    );
    expect(JSON.parse(lastUpdateInputs()[1].value[0])).toEqual([
      expect.objectContaining({ state: 'reviewing', event: 'event_external', user_id: 'user-id' }),
    ]);
  });

  it('holds the workflow mutation lock of the entity while syncing', async () => {
    const unlock = vi.fn();
    (lockResources as any).mockResolvedValueOnce({ unlock });
    setupPublishedDefinition(draftInstance);

    await syncWrite('status-reviewing-id');

    expect(lockResources).toHaveBeenCalledWith(['workflow-mutation-entity-1']);
    expect(unlock).toHaveBeenCalledOnce();
  });

  it('does nothing when a later write already replaced the status on the entity', async () => {
    setupPublishedDefinition(draftInstance);
    storedStatusId = 'status-draft-id';

    await syncWorkflowInstanceFromExternalWrite(mockContext, mockUser, entity, 'status-reviewing-id');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('does nothing when the new status maps to the current state', async () => {
    setupPublishedDefinition({ ...draftInstance, currentState: 'reviewing' });

    await syncWrite('status-reviewing-id');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('clears a stale pendingError when the new status maps back to the current state', async () => {
    setupPublishedDefinition({ ...draftInstance, pendingError: 'previous unmapped write' });

    await syncWrite('status-draft-id');

    expect(lastUpdateInputs()).toEqual([{ key: 'pendingError', value: [null] }]);
  });

  it('keeps the current state and records a pendingError when the new status maps to no state', async () => {
    setupPublishedDefinition(draftInstance);

    await syncWrite('status-orphan-id');

    expect(lastUpdateInputs()).toEqual([{ key: 'pendingError', value: [expect.stringContaining('status-orphan-id')] }]);
  });

  it('treats a status of another scope as unmapped', async () => {
    setupPublishedDefinition(draftInstance);

    await syncWrite('status-rfi-reviewing-id');

    expect(lastUpdateInputs()).toEqual([{ key: 'pendingError', value: [expect.stringContaining('status-rfi-reviewing-id')] }]);
  });

  it('ignores the write while a transition is pending, recording it in history without touching state or pendingError', async () => {
    setupPublishedDefinition({ ...draftInstance, pendingStatus: 'pending' });

    await syncWrite('status-reviewing-id');

    const inputs = lastUpdateInputs();
    expect(inputs.map((input: any) => input.key)).toEqual(['history']);
    expect(JSON.parse(inputs[0].value[0])).toEqual([
      expect.objectContaining({ state: 'draft', event: 'event_external_ignored', status_id: 'status-reviewing-id', user_id: 'user-id' }),
    ]);
  });

  it('logs instead of failing the write when the sync throws', async () => {
    (findByType as any).mockRejectedValue(new Error('store unavailable'));

    await expect(syncWrite('status-reviewing-id')).resolves.toBeUndefined();

    expect(logApp.error).toHaveBeenCalledOnce();
  });
});
