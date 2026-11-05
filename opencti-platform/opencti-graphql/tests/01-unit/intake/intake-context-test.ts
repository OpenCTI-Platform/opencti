import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createGraphqlContext } from '../../../src/http/httpGraphqlContext';
import { createIntakeContext } from '../../../src/intake/intake-context';
import { type IntakeEnvelope, intakeEnvelopeOf, intakeHeadersOf } from '../../../src/intake/intake-envelope';
import { redisGetWork } from '../../../src/database/redis';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';
import { authenticateIntakeWriter, authenticateUserFromRequest } from '../../../src/modules/user/user-domain';
import { isVerifiedFormSubmission } from '../../../src/modules/form/form-submission-context';

// The in-process intake must write under the context the HTTP edge gives a worker's request
// carrying the same headers: both go through intake-context-rules.ts, this test holds them equal.

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn().mockResolvedValue({ otp_mandatory: false, platform_organization: null }),
  getEntitiesMapFromCache: vi.fn().mockResolvedValue(new Map()),
}));
vi.mock('../../../src/database/redis', () => ({ redisGetWork: vi.fn() }));
vi.mock('../../../src/http/httpServer-draft', () => ({ checkDraftInContext: vi.fn() }));
vi.mock('../../../src/modules/form/form-submission-context', () => ({ isVerifiedFormSubmission: vi.fn() }));
vi.mock('../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/user/user-domain')>()),
  authenticateUserFromRequest: vi.fn(),
  authenticateIntakeWriter: vi.fn(),
}));

// What the authentication gives for a bypass writer impersonating the applicant (internalAuthenticateUser)
const applicant = {
  id: 'applicant-1',
  draft_context: 'draft-of-the-applicant',
  capabilities: [],
  groups: [],
  organizations: [],
  origin: { real_authentication_id: 'writer-1', synchronized_upsert: false },
};

const ENVELOPE: IntakeEnvelope = {
  user_id: 'writer-1',
  applicant_id: 'applicant-1',
  work_id: 'work-1',
  draft_id: 'draft-1',
  event_id: 'event-1',
  playbook_id: 'playbook-1',
  synchronized: false,
  previous_standard: 'malware--previous',
  retry_number: 0,
};

const httpContextOf = (envelope: IntakeEnvelope) => {
  const headers = intakeHeadersOf(envelope);
  return createGraphqlContext({ headers, header: (name: string) => headers[name], ip: 'intake' } as any, {} as any);
};

// The fields an ingestion write reads from its context
const written = (context: any) => ({
  workId: context.workId,
  draft_context: context.draft_context,
  eventId: context.eventId,
  previousStandard: context.previousStandard,
  synchronizedUpsert: context.synchronizedUpsert,
  real_authentication_id: context.real_authentication_id,
  form_submission: context.form_submission,
  user_inside_platform_organization: context.user_inside_platform_organization,
  blocked_for_lts_validation: context.blocked_for_lts_validation,
  user: {
    id: context.user.id,
    applicant_id: context.user.origin.applicant_id,
    playbook_id: context.user.origin.playbook_id,
    call_retry_number: context.user.origin.call_retry_number,
  },
});

describe('Intake context', () => {
  beforeEach(() => {
    vi.mocked(authenticateUserFromRequest).mockResolvedValue(applicant as any);
    vi.mocked(authenticateIntakeWriter).mockResolvedValue(applicant as any);
    vi.mocked(redisGetWork).mockResolvedValue({ is_initialized: 'true', form_id: 'form-1' });
    vi.mocked(isVerifiedFormSubmission).mockReturnValue(true);
    vi.mocked(checkDraftInContext).mockReset();
  });

  it('should send a header only for a value set, as pycti', () => {
    expect(intakeHeadersOf({})).toEqual({ 'synchronized-upsert': 'false', 'opencti-retry-number': '0' });
    expect(intakeHeadersOf({ draft_id: '', synchronized: true, retry_number: 2 })).toEqual({ 'opencti-draft-id': '', 'synchronized-upsert': 'true', 'opencti-retry-number': '2' });
  });

  it.each([
    ['every header', ENVELOPE],
    ['no draft header: the applicant\'s own draft', { ...ENVELOPE, draft_id: undefined }],
    ['an empty draft header: live', { ...ENVELOPE, draft_id: '' }],
    ['no work', { ...ENVELOPE, work_id: undefined }],
  ])('should build the context of the HTTP edge for the same headers (%s)', async (_label, envelope) => {
    const http = await httpContextOf(envelope);
    const { context } = await createIntakeContext(envelope, 'intake_test');
    expect(written(context)).toEqual(written(http));
    expect(vi.mocked(authenticateIntakeWriter).mock.calls.at(-1)?.[2]).toEqual(envelope.user_id);
  });

  it('should read back the envelope a context was built from', async () => {
    const { context, user } = await createIntakeContext(ENVELOPE, 'intake_test');
    expect(intakeEnvelopeOf(context, user)).toEqual(ENVELOPE);
  });

  it('should refuse a deleted work and check the draft, as the HTTP edge', async () => {
    vi.mocked(redisGetWork).mockResolvedValue({ is_initialized: 'false' });
    await expect(httpContextOf(ENVELOPE)).rejects.toThrow('Work is no longer alive');
    await expect(createIntakeContext(ENVELOPE, 'intake_test')).rejects.toThrow('Work is no longer alive');
    vi.mocked(redisGetWork).mockResolvedValue({ is_initialized: 'true' });
    await createIntakeContext(ENVELOPE, 'intake_test');
    expect(checkDraftInContext).toHaveBeenCalled();
  });
});
