import { afterEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import { patchAttribute } from '../../../../src/database/middleware';
import { elCount } from '../../../../src/database/engine';
import { addSecurityPlatform } from '../../../../src/modules/securityPlatform/securityPlatform-domain';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { generateStandardId } from '../../../../src/schema/identifier';
import { dispatchHuntRun, isHuntConnectorBoundToRun } from '../../../../src/modules/hunt/hunt-dispatch';
import { HUNT_MESSAGES } from '../../../../src/modules/hunt/hunt-messages';
import { huntRunTransitionLockKey, withHuntLock } from '../../../../src/modules/hunt/hunt-lock';
import { findHuntConnectors, huntConnectorPlatformLockKey, registerHuntConnector } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import type { BasicStoreEntityConnector } from '../../../../src/types/connector';
import type { AuthUser } from '../../../../src/types/user';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
  internalFindByIds: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elCount: vi.fn(),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elCount: vi.fn(async () => 0),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  notify: vi.fn(async (_topic, instance) => instance),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-lock')>(),
  withHuntLock: vi.fn(async (_key, action) => action()),
}));

vi.mock('../../../../src/modules/securityPlatform/securityPlatform-domain', () => ({
  addSecurityPlatform: vi.fn(),
}));

const live = new Date().toISOString();
const connector = (id: string, platform: string, securityPlatformId: string | null) => ({
  internal_id: id,
  id,
  name: `${platform} ${id}`,
  connector_type: 'INTERNAL_HUNT',
  connector_user_id: ADMIN_USER.id,
  hunt_platform: platform,
  hunt_languages: ['spl'],
  hunt_security_platform_id: securityPlatformId,
  updated_at: live,
  created_at: '2026-10-01T00:00:00.000Z',
});

const SPLUNK_PROD = connector('connector-splunk', 'splunk', 'platform-prod');
const SENTINEL_LAB = connector('connector-sentinel', 'sentinel', 'platform-lab');
const TRACKER = connector('connector-tracker', 'internet', null);

// The registered hunt connectors, and the active runs a cancellation reads
const serving = (connectors: object[], runs: object[] = []) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, types) => (types?.includes('Connector') ? connectors : runs) as never);
};

// The connector a registration reads, and the security platform its name stands for when it exists
const loadingRegistration = (current: object | ((id: string) => object), platform: object | null) => {
  vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id, type) => {
    if (type === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM) {
      return platform as never;
    }
    return (typeof current === 'function' ? current(id) : current) as never;
  });
};
const PROD_STANDARD_ID = generateStandardId(ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, { name: 'Prod', identity_class: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM.toLowerCase() }) as string;

const registering = (input: Record<string, unknown>) => registerHuntConnector(testContext, ADMIN_USER, {
  connector_id: SPLUNK_PROD.internal_id,
  platform: 'splunk',
  languages: ['spl'],
  ...input,
} as never);

describe('Hunt connectors and their security platforms', () => {
  afterEach(() => {
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(internalFindByIds).mockReset();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(addSecurityPlatform).mockReset();
    vi.mocked(withHuntLock).mockClear();
    vi.mocked(elCount).mockClear();
    vi.mocked(elCount).mockResolvedValue(0 as never);
  });

  it('should list the connectors of the internet and of the security platforms the user can read only', async () => {
    serving([SPLUNK_PROD, SENTINEL_LAB, TRACKER]);
    vi.mocked(internalFindByIds).mockResolvedValue([{ internal_id: 'platform-lab' }] as never);
    const listed = await findHuntConnectors(testContext, ADMIN_USER);
    expect(listed.map((view) => view.id)).toEqual(['connector-sentinel', 'connector-tracker']);
    expect(vi.mocked(internalFindByIds).mock.calls[0][2]).toEqual(['platform-prod', 'platform-lab']);
  });

  it('should refuse a connector of another kind on a security platform a connector already executes against', async () => {
    serving([SPLUNK_PROD, SENTINEL_LAB]);
    loadingRegistration({ ...SPLUNK_PROD, hunt_security_platform_id: null }, { internal_id: 'platform-lab' });
    await expect(registering({ security_platform_name: 'Lab' })).rejects.toThrow('The security platform Lab is hunted by the sentinel connector');
    // Refused, the registration wrote nothing, to the security platform neither
    expect(addSecurityPlatform).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should create the security platform a registration names only once it is accepted, and never write to an existing one', async () => {
    serving([SPLUNK_PROD]);
    loadingRegistration(SPLUNK_PROD, null);
    vi.mocked(addSecurityPlatform).mockResolvedValue({ internal_id: 'platform-new' } as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...SPLUNK_PROD, ...patch } }) as never);
    expect(await registering({ security_platform_name: 'New SIEM', security_platform_type: 'EDR' })).toMatchObject({ security_platform_id: 'platform-new' });
    expect(addSecurityPlatform).toHaveBeenCalledWith(testContext, ADMIN_USER, { name: 'New SIEM', security_platform_type: 'EDR' });
    // Named again once it exists, the platform is bound as it is: its type is left to its editors
    vi.mocked(addSecurityPlatform).mockClear();
    loadingRegistration(SPLUNK_PROD, { internal_id: 'platform-new', security_platform_type: 'EDR' });
    expect(await registering({ security_platform_name: 'New SIEM', security_platform_type: 'SIEM' })).toMatchObject({ security_platform_id: 'platform-new' });
    expect(addSecurityPlatform).not.toHaveBeenCalled();
  });

  it('should check and bind a connector under a lock per security platform, never an internet connector, and bind every connector under its dispatch lock', async () => {
    serving([SPLUNK_PROD, TRACKER]);
    loadingRegistration(SPLUNK_PROD, { internal_id: 'platform-prod' });
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...SPLUNK_PROD, ...patch } }) as never);
    // The connectors read for the check and the binding both happen while the lock is held
    const heldDuring: number[] = [];
    vi.mocked(withHuntLock).mockImplementationOnce(async (_key, action) => {
      const result = await action();
      heldDuring.push(vi.mocked(fullEntitiesList).mock.calls.length, vi.mocked(patchAttribute).mock.calls.length);
      return result;
    });
    await registering({ security_platform_name: 'Prod' });
    expect(vi.mocked(withHuntLock).mock.calls.map(([key]) => key)).toEqual([huntConnectorPlatformLockKey(PROD_STANDARD_ID), 'hunt_connector_dispatch_connector-splunk']);
    expect(heldDuring).toEqual([1, 1]);
    vi.mocked(withHuntLock).mockClear();
    loadingRegistration(TRACKER, null);
    await registering({ connector_id: TRACKER.internal_id, platform: 'internet', languages: ['url'] });
    expect(vi.mocked(withHuntLock).mock.calls.map(([key]) => key)).toEqual(['hunt_connector_dispatch_connector-tracker']);
    expect(addSecurityPlatform).not.toHaveBeenCalled();
  });

  it('should read the binding again under the dispatch lock, so a connector registered meanwhile against another platform gets no run of the former', async () => {
    const run = { internal_id: 'run-1', hunt_id: 'hunt-1', connector_id: SPLUNK_PROD.internal_id, security_platform_id: 'platform-prod', hunt_run_status: 'queued', hunt_run_mode: 'execute' };
    serving([SPLUNK_PROD]);
    vi.mocked(internalFindByIds).mockResolvedValue([run] as never);
    vi.mocked(withHuntLock).mockImplementationOnce(async (_key, action) => {
      // The registration against another platform held the lock first
      serving([{ ...SPLUNK_PROD, hunt_security_platform_id: 'platform-dr' }]);
      return action();
    });
    expect(await dispatchHuntRun(testContext, run as BasicStoreEntityHuntRun, { internal_id: 'hunt-1' } as BasicStoreEntityHunt)).toBe(false);
    // The lock of the run first, as a retry takes it before dispatching its next attempt, then the lock of the connector
    expect(vi.mocked(withHuntLock).mock.calls.map(([key]) => key)).toEqual([huntRunTransitionLockKey('run-1'), 'hunt_connector_dispatch_connector-splunk']);
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should never send a run cancelled while its dispatch waited for the transition lock of the run', async () => {
    const run = { internal_id: 'run-1', hunt_id: 'hunt-1', connector_id: SPLUNK_PROD.internal_id, security_platform_id: 'platform-prod', hunt_run_status: 'queued', hunt_run_mode: 'execute' };
    serving([SPLUNK_PROD]);
    vi.mocked(internalFindByIds).mockResolvedValue([run] as never);
    vi.mocked(withHuntLock).mockImplementationOnce(async (_key, action) => {
      // The deletion of its hunt cancelled the run while holding the lock first
      vi.mocked(internalFindByIds).mockResolvedValue([{ ...run, hunt_run_status: 'cancelled' }] as never);
      return action();
    });
    expect(await dispatchHuntRun(testContext, run as BasicStoreEntityHuntRun, { internal_id: 'hunt-1' } as BasicStoreEntityHunt)).toBe(false);
    expect(vi.mocked(withHuntLock).mock.calls[0][0]).toEqual(huntRunTransitionLockKey('run-1'));
    expect(elCount).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should hold a run to the limits its connector registered while the dispatch lock was held', async () => {
    const run = { internal_id: 'run-1', hunt_id: 'hunt-1', connector_id: SPLUNK_PROD.internal_id, security_platform_id: 'platform-prod', hunt_run_status: 'queued', hunt_run_mode: 'execute' };
    serving([SPLUNK_PROD]);
    vi.mocked(internalFindByIds).mockResolvedValue([run] as never);
    // One run of the connector is already dispatched, within the default limit of two
    vi.mocked(elCount).mockResolvedValue(1 as never);
    vi.mocked(withHuntLock).mockImplementationOnce(async (_key, action) => {
      // The registration against the same platform held the lock first and lowered the limit to one run at a time
      serving([{ ...SPLUNK_PROD, hunt_max_concurrent_runs: 1 }]);
      return action();
    });
    expect(await dispatchHuntRun(testContext, run as BasicStoreEntityHuntRun, { internal_id: 'hunt-1' } as BasicStoreEntityHunt)).toBe(false);
    expect(elCount).toHaveBeenCalledTimes(1);
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should keep a run queued when its connector stopped while the dispatch lock was awaited', async () => {
    const run = { internal_id: 'run-1', hunt_id: 'hunt-1', connector_id: SPLUNK_PROD.internal_id, security_platform_id: 'platform-prod', hunt_run_status: 'queued', hunt_run_mode: 'execute' };
    serving([SPLUNK_PROD]);
    vi.mocked(internalFindByIds).mockResolvedValue([run] as never);
    vi.mocked(withHuntLock).mockImplementationOnce(async (_key, action) => {
      serving([{ ...SPLUNK_PROD, updated_at: '2026-01-01T00:00:00.000Z' }]);
      return action();
    });
    expect(await dispatchHuntRun(testContext, run as BasicStoreEntityHuntRun, { internal_id: 'hunt-1' } as BasicStoreEntityHunt)).toBe(false);
    expect(elCount).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should refuse a registration whose connector got another user while the binding waited for its lock', async () => {
    const connectorUser = { ...ADMIN_USER, id: 'connector-user-1', capabilities: [{ name: 'CONNECTORAPI' }] } as AuthUser;
    serving([SPLUNK_PROD]);
    let reads = 0;
    loadingRegistration(() => {
      reads += 1;
      return { ...SPLUNK_PROD, connector_user_id: reads === 1 ? connectorUser.id : 'connector-user-2' };
    }, null);
    await expect(registerHuntConnector(testContext, connectorUser, { connector_id: SPLUNK_PROD.internal_id, platform: 'splunk', languages: ['spl'], security_platform_name: 'Prod' } as never))
      .rejects.toThrow('A hunt connector can only register itself');
    expect(addSecurityPlatform).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should let connectors of the same kind share a security platform', async () => {
    const replica = connector('connector-splunk-2', 'splunk', 'platform-prod');
    serving([SPLUNK_PROD, replica]);
    loadingRegistration(SPLUNK_PROD, { internal_id: 'platform-prod' });
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...SPLUNK_PROD, ...patch } }) as never);
    expect(await registering({ security_platform_name: 'Prod' })).toMatchObject({ security_platform_id: 'platform-prod' });
    // Registered again against the same platform: its runs are left as they are
    expect(vi.mocked(fullEntitiesList).mock.calls.filter(([, , types]) => types?.includes('Hunt-Run'))).toHaveLength(0);
  });

  it('should cancel the runs of the former platform of a connector registered against another one', async () => {
    const former = { internal_id: 'run-former', hunt_id: 'hunt-1', connector_id: SPLUNK_PROD.internal_id, security_platform_id: 'platform-prod', hunt_run_status: 'queued', hunt_run_mode: 'execute' };
    serving([SPLUNK_PROD], [former]);
    loadingRegistration((id) => (id === 'run-former' ? former : SPLUNK_PROD), null);
    vi.mocked(addSecurityPlatform).mockResolvedValue({ internal_id: 'platform-dr' } as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, id, _type, patch) => ({ element: { ...(id === 'run-former' ? former : SPLUNK_PROD), ...patch } }) as never);
    await registering({ security_platform_name: 'Disaster recovery' });
    const runsQuery = vi.mocked(fullEntitiesList).mock.calls.find(([, , types]) => types?.includes('Hunt-Run'));
    expect(runsQuery?.[3]?.filters?.filters).toEqual([
      { key: ['connector_id'], values: [SPLUNK_PROD.internal_id] },
      { key: ['security_platform_id'], values: ['platform-dr'], operator: 'not_eq' },
    ]);
    const cancel = vi.mocked(patchAttribute).mock.calls.find(([, , id]) => id === 'run-former');
    expect(cancel?.[4]).toMatchObject({ hunt_run_status: 'cancelled', error_message: HUNT_MESSAGES.runCancelledConnectorRebound });
  });

  it('should never send a run to its connector once the connector executes against another platform', async () => {
    const run = { internal_id: 'run-1', hunt_id: 'hunt-1', connector_id: SPLUNK_PROD.internal_id, security_platform_id: 'platform-lab', hunt_run_status: 'queued', hunt_run_mode: 'execute' };
    serving([SPLUNK_PROD]);
    expect(await dispatchHuntRun(testContext, run as BasicStoreEntityHuntRun, { internal_id: 'hunt-1' } as BasicStoreEntityHunt)).toBe(false);
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(isHuntConnectorBoundToRun(SPLUNK_PROD as unknown as BasicStoreEntityConnector, { security_platform_id: 'platform-prod' })).toBe(true);
    expect(isHuntConnectorBoundToRun(TRACKER as unknown as BasicStoreEntityConnector, { security_platform_id: null })).toBe(true);
    expect(isHuntConnectorBoundToRun(TRACKER as unknown as BasicStoreEntityConnector, { security_platform_id: 'platform-prod' })).toBe(false);
  });
});
