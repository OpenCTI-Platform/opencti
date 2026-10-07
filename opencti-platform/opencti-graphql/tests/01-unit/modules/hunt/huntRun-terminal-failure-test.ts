import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { internalLoadById, storeLoadById, topEntitiesList } from '../../../../src/database/middleware-loader';
import { patchAttribute } from '../../../../src/database/middleware';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { HUNT_MESSAGES } from '../../../../src/modules/hunt/hunt-messages';
import { findHuntTranslation, findHuntTranslations, huntLogicFingerprint, huntRunFailureReason, isDeterministicHuntFailure } from '../../../../src/modules/hunt/hunt-logic';
import { translationItem } from '../../../../src/modules/hunt/hunt-readiness';
import { HuntReadinessStatus } from '../../../../src/generated/graphql';
import { computeHuntPlaybookOutcome } from '../../../../src/modules/hunt/hunt-playbook';
import { reportHuntRun, startHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalLoadById: vi.fn(),
  storeLoadById: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  notify: vi.fn(async (_topic, instance) => instance),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-lock')>(),
  withHuntLock: vi.fn(async (_key, action) => action()),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  listHuntConnectors: vi.fn(async () => []),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

const UDM_FAILURE = 'HuntTranslationError: Sigma conversion failed: Invalid UDM field: Field query is not a UDM field (logsource: dns)';
const hunt = { internal_id: 'hunt-1', name: 'DNS tunnelling', hunt_type: 'sigma', sigma_rule: 'title: DNS', hunt_status: 'active', escalation_threshold: 10 } as unknown as BasicStoreEntityHunt;
const running = {
  internal_id: 'run-1',
  hunt_id: 'hunt-1',
  hunt_run_status: 'running',
  hunt_run_mode: 'execute',
  hunt_run_trigger: 'manual',
  connector_name: 'Google SecOps Hunt',
  attempt: 1,
  verdict: 'pending',
  work_id: 'work-1',
} as unknown as BasicStoreEntityHuntRun;

// Every patch of the run, merged in order: the state the run ends in
const patches = () => vi.mocked(patchAttribute).mock.calls.map((call) => call[4] as Record<string, unknown>);
const finalState = () => Object.assign({}, ...patches());

describe('Deterministic hunt failures', () => {
  it('should follow the connector when it says, and read the error when it does not', () => {
    expect(isDeterministicHuntFailure('failed', 'HuntExecutionError: HTTP 400 search rejected', false)).toBe(true);
    expect(isDeterministicHuntFailure('failed', UDM_FAILURE, true)).toBe(false);
    expect(isDeterministicHuntFailure('failed', UDM_FAILURE, null)).toBe(true);
    expect(isDeterministicHuntFailure('failed', 'HuntRequestError: Invalid hunt run message', undefined)).toBe(true);
    expect(isDeterministicHuntFailure('failed', 'Sigma conversion failed: unsupported logsource dns', undefined)).toBe(true);
    expect(isDeterministicHuntFailure('failed', 'HuntExecutionError: HTTP 503 service unavailable', undefined)).toBe(false);
    expect(isDeterministicHuntFailure('failed', 'HuntAccessDeniedError: Access denied', undefined)).toBe(false);
    // A timeout is never deterministic, whatever the connector says
    expect(isDeterministicHuntFailure('timeout', UDM_FAILURE, false)).toBe(false);
  });

  it('should explain a run that failed for good, and nothing for a run that will be retried', () => {
    const translation = huntRunFailureReason({ hunt_run_status: 'failed', failure_retryable: false, error_message: UDM_FAILURE, connector_name: 'Google SecOps Hunt' });
    expect(translation?.template).toEqual(HUNT_MESSAGES.runFailedTranslation);
    expect(translation?.message).toContain('Google SecOps Hunt cannot translate the hunt logic');
    const rejected = huntRunFailureReason({ hunt_run_status: 'failed', failure_retryable: false, error_message: 'HuntExecutionError: HTTP 422', connector_name: 'Splunk Hunt' });
    expect(rejected?.template).toEqual(HUNT_MESSAGES.runFailedRejected);
    expect(huntRunFailureReason({ hunt_run_status: 'failed', failure_retryable: true, error_message: 'HuntExecutionError: HTTP 503', connector_name: 'Splunk Hunt' })).toBeNull();
  });
});

describe('Report of a failed hunt run', () => {
  beforeEach(() => {
    vi.mocked(storeLoadById).mockResolvedValue(running as never);
    vi.mocked(internalLoadById).mockResolvedValue(hunt as never);
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...running, ...finalState(), ...patch } }) as never);
  });

  afterEach(() => {
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(internalLoadById).mockReset();
  });

  it('should end a translation failure for good: no retry, no automatic inconclusive verdict', async () => {
    const run = await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'failed', error: UDM_FAILURE } as never);
    const state = finalState();
    expect(state.hunt_run_status).toEqual('failed');
    expect(state.failure_retryable).toBe(false);
    expect(state.next_retry_at).toBeUndefined();
    expect(state.verdict).toEqual('pending');
    expect(state.verdict_source).toEqual('auto');
    expect(huntRunFailureReason(run as BasicStoreEntityHuntRun)?.template).toEqual(HUNT_MESSAGES.runFailedTranslation);
  });

  it('should end a failure the connector reports not retryable for good', async () => {
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'failed', error: 'HuntExecutionError: YARA-L rule does not compile', retryable: false } as never);
    expect(finalState()).toMatchObject({ failure_retryable: false, verdict: 'pending' });
    expect(finalState().next_retry_at).toBeUndefined();
  });

  it('should accept the same terminal report sent again once the run is finalized, and refuse another outcome', async () => {
    const finalized = { ...running, hunt_run_status: 'completed', hits_count: 4, verdict: 'pending', verdict_source: 'auto', completed_at: '2026-10-07T21:00:00.000Z' };
    vi.mocked(storeLoadById).mockResolvedValue(finalized as never);
    vi.mocked(updateHuntRunInformation).mockClear();
    const again = await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 4 } as never);
    expect(again).toMatchObject({ hunt_run_status: 'completed', hits_count: 4, verdict_source: 'auto' });
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(updateHuntRunInformation).not.toHaveBeenCalled();
    await expect(reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'failed', error: 'HuntExecutionError: HTTP 503' } as never))
      .rejects.toThrow('The hunt run is already terminated');
  });

  it('should still retry a transient failure, inconclusive until its retry', async () => {
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'failed', error: 'HuntExecutionError: HTTP 503 service unavailable' } as never);
    const state = finalState();
    expect(state.failure_retryable).toBe(true);
    expect(typeof state.next_retry_at).toEqual('string');
    expect(state.verdict).toEqual('inconclusive');
  });
});

describe('Translation of the current logic of a hunt', () => {
  afterEach(() => {
    vi.mocked(topEntitiesList).mockReset();
    vi.mocked(topEntitiesList).mockResolvedValue([] as never);
    vi.mocked(storeLoadById).mockReset();
  });

  const failedPreview = { ...running, hunt_run_mode: 'preview', hunt_run_status: 'failed', failure_retryable: false, error_message: UDM_FAILURE };

  it('should read the runs of the current logic only, the most recent telling first', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([
      { ...running, hunt_run_status: 'failed', failure_retryable: true },
      failedPreview,
      { ...running, hunt_run_status: 'completed' },
    ] as never);
    const translation = await findHuntTranslation(testContext, ADMIN_USER, hunt);
    expect(translation?.state).toEqual('failed');
    const filters = (vi.mocked(topEntitiesList).mock.calls[0][3] as { filters: { filters: unknown[] } }).filters.filters;
    expect(filters).toContainEqual({ key: ['hunt_logic_fingerprint'], values: [huntLogicFingerprint(hunt)] });
    expect(huntLogicFingerprint({ ...hunt, sigma_rule: 'title: DNS v2' })).not.toEqual(huntLogicFingerprint(hunt));
  });

  it('should say nothing of a logic no run has translated yet, nor of indicator lookups', async () => {
    expect(await findHuntTranslation(testContext, ADMIN_USER, hunt)).toBeNull();
    expect(await findHuntTranslation(testContext, ADMIN_USER, { ...hunt, hunt_type: 'indicators' })).toBeNull();
    expect(topEntitiesList).toHaveBeenCalledTimes(1);
  });

  it('should refuse Run now for a logic that failed to translate for good, before any run is created', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(hunt as never);
    vi.mocked(topEntitiesList).mockResolvedValue([failedPreview] as never);
    await expect(startHuntRuns(testContext, ADMIN_USER, 'hunt-1', {}))
      .rejects.toThrow('The hunt cannot run: Google SecOps Hunt cannot translate the hunt logic: HuntTranslationError: Sigma conversion failed: Invalid UDM field');
  });

  it('should tell the translation of each security platform, and block the activation only when every platform failed', async () => {
    const failedOnSecOps = { ...failedPreview, internal_id: 'run-secops', security_platform_id: 'platform-secops' };
    const translatedOnSplunk = { ...running, internal_id: 'run-splunk', hunt_run_status: 'completed', connector_name: 'Splunk Hunt', security_platform_id: 'platform-splunk' };
    const olderOnSecOps = { ...running, internal_id: 'run-secops-old', hunt_run_status: 'completed', security_platform_id: 'platform-secops' };
    vi.mocked(topEntitiesList).mockResolvedValue([failedOnSecOps, translatedOnSplunk, olderOnSecOps] as never);
    expect((await findHuntTranslations(testContext, ADMIN_USER, hunt)).map(({ state, run }) => [state, run.internal_id]))
      .toEqual([['failed', 'run-secops'], ['translated', 'run-splunk']]);
    const partial = await findHuntTranslation(testContext, ADMIN_USER, hunt);
    expect(partial).toMatchObject({ state: 'translated', run: { internal_id: 'run-splunk' } });
    expect(partial?.failedOn.map(({ run }) => run.internal_id)).toEqual(['run-secops']);
    // A failure on some platforms only warns: the hunt runs on the others
    expect(translationItem(partial)).toEqual([expect.objectContaining({ status: HuntReadinessStatus.Warning, message: expect.stringContaining('Google SecOps Hunt cannot translate') })]);
    vi.mocked(topEntitiesList).mockResolvedValue([failedOnSecOps] as never);
    const failed = await findHuntTranslation(testContext, ADMIN_USER, hunt);
    expect(failed?.state).toEqual('failed');
    expect(translationItem(failed)).toEqual([expect.objectContaining({ status: HuntReadinessStatus.Unmet })]);
  });

  it('should leave a run that failed for good out of the verdicts a playbook matches', () => {
    const outcome = computeHuntPlaybookOutcome([{ ...failedPreview, hunt_run_mode: 'execute', verdict: 'pending' } as BasicStoreEntityHuntRun]);
    expect(outcome.runs_count).toEqual(1);
    expect(outcome.verdicts).toEqual([]);
    expect(outcome.proposed_verdicts).toEqual([]);
  });
});
