import { beforeEach, describe, expect, it, vi } from 'vitest';
import { caseRfiCreationHandler, type CaseRfiHookProgress, isRetryableHookError } from '../../../src/manager/investigationRunManager';
import { addInvestigationRun } from '../../../src/modules/investigationRun/investigationRun-domain';
import { resolveUserByIdFromCache } from '../../../src/modules/user/user-domain';
import { DatabaseError, ForbiddenAccess, FunctionalError, LockTimeoutError, MissingReferenceError } from '../../../src/config/errors';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { InvestigationRunTrigger } from '../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { DataEvent, SseEvent } from '../../../src/types/event';
import type { BasicStoreEntityInvestigationPolicy } from '../../../src/modules/investigationRun/investigationRun-types';

vi.mock('../../../src/modules/investigationRun/investigationRun-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/modules/investigationRun/investigationRun-domain')>(),
  addInvestigationRun: vi.fn(),
}));

vi.mock('../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/modules/user/user-domain')>(),
  resolveUserByIdFromCache: vi.fn(),
}));

const context = { source: 'test' } as unknown as AuthContext;
const policy = { internal_id: 'policy-1', run_as_id: 'user-1' } as BasicStoreEntityInvestigationPolicy;
const runUser = { id: 'user-1' } as AuthUser;

const rfiCreation = (eventId: string, rfiId: string) => ({
  id: eventId,
  event: 'create',
  data: { type: 'create', data: { extensions: { [STIX_EXT_OCTI]: { type: ENTITY_TYPE_CONTAINER_CASE_RFI, id: rfiId } } } },
}) as unknown as SseEvent<DataEvent>;

const otherEvent = (eventId: string) => ({
  id: eventId,
  event: 'update',
  data: { type: 'update', data: { extensions: { [STIX_EXT_OCTI]: { type: 'Report', id: 'report-1' } } } },
}) as unknown as SseEvent<DataEvent>;

describe('Case Autopilot manager - request for information hook', () => {
  beforeEach(() => {
    vi.mocked(addInvestigationRun).mockReset();
    vi.mocked(resolveUserByIdFromCache).mockReset();
    vi.mocked(resolveUserByIdFromCache).mockResolvedValue(runUser);
  });

  it('retries technical failures and skips refusals', () => {
    expect(isRetryableHookError(DatabaseError('Elasticsearch is not reachable'))).toBe(true);
    expect(isRetryableHookError(LockTimeoutError({ participantIds: ['rfi-1'] }))).toBe(true);
    expect(isRetryableHookError(new Error('socket hang up'))).toBe(true);
    expect(isRetryableHookError(FunctionalError('The entity to investigate cannot be found'))).toBe(false);
    expect(isRetryableHookError(ForbiddenAccess())).toBe(false);
    expect(isRetryableHookError(MissingReferenceError({ ids: ['rfi-1'] }))).toBe(false);
  });

  it('starts one run per new request for information and handles the whole batch', async () => {
    vi.mocked(addInvestigationRun).mockResolvedValue({} as never);
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([rfiCreation('1-0', 'rfi-1'), otherEvent('2-0'), rfiCreation('3-0', 'rfi-2')]);
    expect(vi.mocked(addInvestigationRun).mock.calls.map((call) => call[2])).toEqual(['rfi-1', 'rfi-2']);
    expect(vi.mocked(addInvestigationRun).mock.calls[0][4]).toEqual({ trigger: InvestigationRunTrigger.CaseRfiCreation, runAsUserId: 'user-1' });
    expect(progress).toEqual({ handledEventId: '3-0', retry: false });
  });

  it('moves past a request it may not investigate', async () => {
    vi.mocked(addInvestigationRun)
      .mockRejectedValueOnce(FunctionalError('Case Autopilot investigates incidents, cases, indicators and observables only'))
      .mockResolvedValueOnce({} as never);
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([rfiCreation('1-0', 'rfi-1'), rfiCreation('2-0', 'rfi-2')]);
    expect(addInvestigationRun).toHaveBeenCalledTimes(2);
    expect(progress).toEqual({ handledEventId: '2-0', retry: false });
  });

  it('stops on a technical failure and keeps the failed request for the next run', async () => {
    vi.mocked(addInvestigationRun)
      .mockResolvedValueOnce({} as never)
      .mockRejectedValueOnce(DatabaseError('Elasticsearch is not reachable'));
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([rfiCreation('1-0', 'rfi-1'), rfiCreation('2-0', 'rfi-2'), rfiCreation('3-0', 'rfi-3')]);
    expect(vi.mocked(addInvestigationRun).mock.calls.map((call) => call[2])).toEqual(['rfi-1', 'rfi-2']);
    expect(progress).toEqual({ handledEventId: '1-0', retry: true });
  });

  it('keeps the cursor in place when the first request already fails', async () => {
    vi.mocked(addInvestigationRun).mockRejectedValueOnce(LockTimeoutError({ participantIds: ['rfi-1'] }));
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([rfiCreation('1-0', 'rfi-1')]);
    expect(progress).toEqual({ handledEventId: null, retry: true });
  });

  it('does not wait for an identity when the batch holds no new request for information', async () => {
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([otherEvent('1-0'), otherEvent('2-0')]);
    expect(resolveUserByIdFromCache).not.toHaveBeenCalled();
    expect(addInvestigationRun).not.toHaveBeenCalled();
    expect(progress).toEqual({ handledEventId: '2-0', retry: false });
  });
});
