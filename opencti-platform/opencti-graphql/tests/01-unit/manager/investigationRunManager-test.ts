import { beforeEach, describe, expect, it, vi } from 'vitest';
import { caseRfiCreationHandler, type CaseRfiHookProgress, isRetryableHookError, nextCaseRfiHookPosition, startCaseRfiHook } from '../../../src/manager/investigationRunManager';
import { addInvestigationRun, investigationIdentityContext, resolveRunIdentity } from '../../../src/modules/investigationRun/investigationRun-domain';
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
  investigationIdentityContext: vi.fn(),
  resolveRunIdentity: vi.fn(),
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
    vi.mocked(resolveRunIdentity).mockReset();
    vi.mocked(resolveRunIdentity).mockResolvedValue(runUser);
    vi.mocked(investigationIdentityContext).mockReset();
    vi.mocked(investigationIdentityContext).mockImplementation(async (source, user) => ({ source, user, user_inside_platform_organization: true }) as unknown as AuthContext);
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
    // Read as the policy identity, with its platform organization membership, not with the bare manager context.
    expect(vi.mocked(investigationIdentityContext)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(investigationIdentityContext).mock.calls[0][1]).toBe(runUser);
    expect(vi.mocked(addInvestigationRun).mock.calls[0][0]).toMatchObject({ user: runUser, user_inside_platform_organization: true });
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

  it('keeps the requests for the next run while the identity of the policy does not resolve', async () => {
    vi.mocked(resolveRunIdentity).mockResolvedValueOnce(null);
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([otherEvent('1-0'), rfiCreation('2-0', 'rfi-1'), otherEvent('3-0')]);
    expect(addInvestigationRun).not.toHaveBeenCalled();
    expect(progress).toEqual({ handledEventId: '1-0', retry: true });
  });

  it('keeps the cursor in place when the first request already fails', async () => {
    vi.mocked(addInvestigationRun).mockRejectedValueOnce(LockTimeoutError({ participantIds: ['rfi-1'] }));
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([rfiCreation('1-0', 'rfi-1')]);
    expect(progress).toEqual({ handledEventId: null, retry: true });
  });

  it('stores the starting position of a policy read for the first time when its first request fails', async () => {
    vi.mocked(addInvestigationRun).mockRejectedValueOnce(LockTimeoutError({ participantIds: ['rfi-1'] }));
    const { startEventId, progress } = startCaseRfiHook({ last_event_id: null }, 1000);
    expect(startEventId).toBe('1000-0');
    await caseRfiCreationHandler(context, policy, progress)([rfiCreation('1001-0', 'rfi-1'), rfiCreation('1002-0', 'rfi-2')]);
    // The next run reads again from 1000-0, so the failed request is retried.
    expect(nextCaseRfiHookPosition(progress, '1002-0')).toBe('1000-0');
    expect(startCaseRfiHook({ last_event_id: '900-0' }, 1000).startEventId).toBe('900-0');
    expect(nextCaseRfiHookPosition({ handledEventId: '1000-0', retry: false }, '1002-0')).toBe('1002-0');
  });

  it('does not wait for an identity when the batch holds no new request for information', async () => {
    const progress: CaseRfiHookProgress = { handledEventId: null, retry: false };
    await caseRfiCreationHandler(context, policy, progress)([otherEvent('1-0'), otherEvent('2-0')]);
    expect(resolveRunIdentity).not.toHaveBeenCalled();
    expect(addInvestigationRun).not.toHaveBeenCalled();
    expect(progress).toEqual({ handledEventId: '2-0', retry: false });
  });
});
