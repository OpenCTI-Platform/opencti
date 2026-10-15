import { beforeEach, describe, expect, it, vi } from 'vitest';
import { redisGetWork } from '../../../../src/database/redis';
import { canSubmitFormTo, isVerifiedFormSubmission } from '../../../../src/modules/form/form-submission-context';

vi.mock('../../../../src/database/redis', () => ({
  redisGetWork: vi.fn(),
}));

const caps = (...names: string[]) => names.map((name) => ({ name }));
const applicant = (overrides: Record<string, any> = {}) => ({
  id: 'applicant-1',
  capabilities: caps('KNOWLEDGE_KNFORMINTAKE'),
  capabilitiesInDraft: [],
  ...overrides,
});
// The worker authenticates with its own credential and impersonates the applicant
const contextOf = (user: any, overrides: Record<string, any> = {}) => ({ user, workId: 'work-1', real_authentication_id: 'worker-1', ...overrides }) as any;
const work = (overrides: Record<string, any> = {}) => ({
  is_initialized: 'true',
  form_id: 'form-1',
  form_applicant_id: 'applicant-1',
  form_draft_id: '',
  ...overrides,
});

describe('isVerifiedFormSubmission', () => {
  beforeEach(() => {
    vi.mocked(redisGetWork).mockReset();
    vi.mocked(redisGetWork).mockResolvedValue(work() as any);
  });

  it('should verify the import of a form submission made by the form-only applicant', async () => {
    expect(await isVerifiedFormSubmission(contextOf(applicant()))).toBe(true);
  });

  it('should not trust a request that is not impersonated by a privileged credential', async () => {
    // the credential is the applicant's own, or the context does not know who authenticated
    expect(await isVerifiedFormSubmission(contextOf(applicant(), { real_authentication_id: 'applicant-1' }))).toBe(false);
    expect(await isVerifiedFormSubmission(contextOf(applicant(), { real_authentication_id: undefined }))).toBe(false);
  });

  it('should not verify without a work id', async () => {
    expect(await isVerifiedFormSubmission(contextOf(applicant(), { workId: undefined }))).toBe(false);
    expect(redisGetWork).not.toHaveBeenCalled();
  });

  it('should reject a work that is not a live form submission of this applicant', async () => {
    const context = contextOf(applicant());
    vi.mocked(redisGetWork).mockResolvedValue(work({ is_initialized: 'false' }) as any);
    expect(await isVerifiedFormSubmission(context)).toBe(false);
    vi.mocked(redisGetWork).mockResolvedValue({ is_initialized: 'true' } as any); // a work of another kind
    expect(await isVerifiedFormSubmission(context)).toBe(false);
    vi.mocked(redisGetWork).mockResolvedValue(work({ form_applicant_id: 'someone-else' }) as any);
    expect(await isVerifiedFormSubmission(context)).toBe(false);
  });

  it('should require the request to target the draft of the submission', async () => {
    vi.mocked(redisGetWork).mockResolvedValue(work({ form_draft_id: 'draft-1' }) as any);
    expect(await isVerifiedFormSubmission(contextOf(applicant(), { draft_context: 'draft-1' }))).toBe(true);
    expect(await isVerifiedFormSubmission(contextOf(applicant(), { draft_context: 'other-draft' }))).toBe(false);
    expect(await isVerifiedFormSubmission(contextOf(applicant()))).toBe(false);
    // a submission without draft cannot be replayed inside a draft
    vi.mocked(redisGetWork).mockResolvedValue(work() as any);
    expect(await isVerifiedFormSubmission(contextOf(applicant(), { draft_context: 'draft-1' }))).toBe(false);
  });

  it('should require the form capability in the scope of the destination', async () => {
    const withoutCapability = applicant({ capabilities: caps('KNOWLEDGE_KNASKIMPORT') });
    expect(await isVerifiedFormSubmission(contextOf(withoutCapability))).toBe(false);
    // granted in draft only: valid for a draft destination, not for the main one
    const draftOnly = applicant({ capabilities: [], capabilitiesInDraft: caps('KNOWLEDGE_KNFORMINTAKE') });
    expect(await isVerifiedFormSubmission(contextOf(draftOnly))).toBe(false);
    vi.mocked(redisGetWork).mockResolvedValue(work({ form_draft_id: 'draft-1' }) as any);
    expect(await isVerifiedFormSubmission(contextOf(draftOnly, { draft_context: 'draft-1' }))).toBe(true);
  });
});

describe('canSubmitFormTo', () => {
  it('should accept Create / Update knowledge or the form capability, by scope', () => {
    expect(canSubmitFormTo(applicant({ capabilities: caps('KNOWLEDGE_KNUPDATE') }) as any, false)).toBe(true);
    expect(canSubmitFormTo(applicant() as any, false)).toBe(true);
    expect(canSubmitFormTo(applicant({ capabilities: caps('KNOWLEDGE_KNASKIMPORT') }) as any, true)).toBe(false);
    const draftOnly = applicant({ capabilities: [], capabilitiesInDraft: caps('KNOWLEDGE_KNUPDATE') }) as any;
    expect(canSubmitFormTo(draftOnly, false)).toBe(false);
    expect(canSubmitFormTo(draftOnly, true)).toBe(true);
  });

  it('should keep accepting Import knowledge granted in the draft scope for a draft destination, and nothing else', () => {
    const importInDraft = applicant({ capabilities: [], capabilitiesInDraft: caps('KNOWLEDGE_KNASKIMPORT') }) as any;
    expect(canSubmitFormTo(importInDraft, true)).toBe(true);
    // not for the main destination
    expect(canSubmitFormTo(importInDraft, false)).toBe(false);
    // Import knowledge granted in the main scope only does not open a draft destination (same as the directive)
    const importInMain = applicant({ capabilities: caps('KNOWLEDGE_KNASKIMPORT'), capabilitiesInDraft: [] }) as any;
    expect(canSubmitFormTo(importInMain, true)).toBe(false);
    expect(canSubmitFormTo(importInMain, false)).toBe(false);
  });

  it('should not verify the import of a submission for an applicant that only has Import knowledge', async () => {
    vi.mocked(redisGetWork).mockResolvedValue(work({ form_draft_id: 'draft-1' }) as any);
    const importInDraft = applicant({ capabilities: [], capabilitiesInDraft: caps('KNOWLEDGE_KNASKIMPORT') });
    expect(await isVerifiedFormSubmission(contextOf(importInDraft, { draft_context: 'draft-1' }))).toBe(false);
  });
});
