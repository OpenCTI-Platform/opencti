import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createEntity } from '../../../../src/database/middleware';
import { notify } from '../../../../src/database/redis';
import { addHunt } from '../../../../src/modules/hunt/hunt-domain';
import { computeHuntReadiness } from '../../../../src/modules/hunt/hunt-readiness';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { HuntType } from '../../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createEntity: vi.fn(),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  notify: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-readiness', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-readiness')>(),
  computeHuntReadiness: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

const MISSING_CONNECTOR = 'No hunt connector can run it on the platforms of its scope: deploy a hunt connector or widen the scope';
const unmet = { ready: false, items: [{ key: 'connector', status: 'unmet', template: MISSING_CONNECTOR, values: [], message: MISSING_CONNECTOR }] };
const ready = { ready: true, items: [{ key: 'connector', status: 'met', template: 'ok', values: [], message: 'ok' }] };
// A hunt with its logic and no technique to resolve
const huntInput = { name: 'Readiness at creation', hunt_type: HuntType.Telemetry, native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr' }] };

const createdStatus = () => (vi.mocked(createEntity).mock.calls[0][2] as { hunt_status: string }).hunt_status;

describe('Readiness of a hunt created active', () => {
  beforeEach(() => {
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => ({ ...input, internal_id: 'hunt-1' }));
    vi.mocked(notify).mockImplementation(async (_topic, element) => element);
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
  });

  afterEach(() => {
    vi.mocked(createEntity).mockReset();
    vi.mocked(computeHuntReadiness).mockReset();
  });

  it('should refuse an explicitly active hunt that cannot run, with the sentence of the activation', async () => {
    vi.mocked(computeHuntReadiness).mockResolvedValue(unmet as never);
    await expect(addHunt(testContext, ADMIN_USER, { ...huntInput, hunt_status: 'active' } as never))
      .rejects.toThrow(`This hunt cannot be activated: ${MISSING_CONNECTOR}`);
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should start a hunt created without a status as a draft while it cannot run', async () => {
    vi.mocked(computeHuntReadiness).mockResolvedValue(unmet as never);
    await addHunt(testContext, ADMIN_USER, huntInput as never);
    expect(createdStatus()).toEqual('draft');
  });

  it('should keep a hunt created without a status active when it can run', async () => {
    vi.mocked(computeHuntReadiness).mockResolvedValue(ready as never);
    await addHunt(testContext, ADMIN_USER, huntInput as never);
    expect(createdStatus()).toEqual('active');
  });

  it('should not check a hunt pack upserting a hunt that is already active', async () => {
    await addHunt(testContext, ADMIN_USER, { ...huntInput, hunt_status: 'active' } as never, { upsertedStatus: 'active' });
    expect(computeHuntReadiness).not.toHaveBeenCalled();
    expect(createdStatus()).toEqual('active');
  });

  it('should keep the status of a hunt replicated by a STIX import or a synchronization', async () => {
    await addHunt(testContext, ADMIN_USER, { ...huntInput, hunt_status: 'active', stix_id: 'hunt--4b1b1c7e-7f4c-4c8e-9a51-2f1c3d5e6a7b' } as never);
    await addHunt({ ...testContext, synchronizedUpsert: true }, ADMIN_USER, { ...huntInput, hunt_status: 'active' } as never);
    expect(computeHuntReadiness).not.toHaveBeenCalled();
    expect(vi.mocked(createEntity).mock.calls.map((call) => (call[2] as { hunt_status: string }).hunt_status)).toEqual(['active', 'active']);
  });

  it('should not check a hunt created in a draft workspace, which runs once the draft is validated', async () => {
    await addHunt({ ...testContext, draft_context: 'draft-1' }, ADMIN_USER, { ...huntInput, hunt_status: 'active' } as never);
    expect(computeHuntReadiness).not.toHaveBeenCalled();
    expect(createdStatus()).toEqual('active');
  });
});
