import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createGraphqlContext } from '../../../src/http/httpGraphqlContext';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';
import { redisGetWork } from '../../../src/database/redis';
import { isVerifiedFormSubmission } from '../../../src/modules/form/form-submission-context';

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({ createAuthenticatedContext: vi.fn() }));
vi.mock('../../../src/http/httpServer-draft', () => ({ checkDraftInContext: vi.fn() }));
vi.mock('../../../src/database/redis', () => ({ redisGetWork: vi.fn() }));
vi.mock('../../../src/modules/form/form-submission-context', () => ({ isVerifiedFormSubmission: vi.fn() }));

const req = {} as any;
const res = {} as any;

describe('createGraphqlContext', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('should not look for a form submission outside of a work', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: { id: 'user-1' } } as any);
    const context: any = await createGraphqlContext(req, res);
    expect(context.form_submission).toBeUndefined();
    expect(redisGetWork).not.toHaveBeenCalled();
    expect(isVerifiedFormSubmission).not.toHaveBeenCalled();
    expect(checkDraftInContext).toHaveBeenCalledOnce();
  });

  it('should refuse a request bound to a work that is not alive, without verifying anything', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: { id: 'user-1' }, workId: 'work-1' } as any);
    vi.mocked(redisGetWork).mockResolvedValue({ is_initialized: 'false' });
    await expect(createGraphqlContext(req, res)).rejects.toThrow();
    expect(isVerifiedFormSubmission).not.toHaveBeenCalled();
    expect(checkDraftInContext).not.toHaveBeenCalled();
  });

  it('should flag a live work whose import is verified as a form submission', async () => {
    const executeContext = { user: { id: 'user-1' }, workId: 'work-1' };
    vi.mocked(createAuthenticatedContext).mockResolvedValue(executeContext as any);
    const work = { is_initialized: 'true', form_id: 'form-1' };
    vi.mocked(redisGetWork).mockResolvedValue(work);
    vi.mocked(isVerifiedFormSubmission).mockReturnValue(true);
    const context: any = await createGraphqlContext(req, res);
    // the work hash is read once, and given to the verification
    expect(redisGetWork).toHaveBeenCalledOnce();
    expect(isVerifiedFormSubmission).toHaveBeenCalledWith(executeContext, work);
    expect(context.form_submission).toBe(true);
  });

  it('should not flag a live work that is not a verified form submission', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: { id: 'user-1' }, workId: 'work-1' } as any);
    vi.mocked(redisGetWork).mockResolvedValue({ is_initialized: 'true' });
    vi.mocked(isVerifiedFormSubmission).mockReturnValue(false);
    const context: any = await createGraphqlContext(req, res);
    expect(context.form_submission).toBe(false);
    expect(checkDraftInContext).toHaveBeenCalledOnce();
  });
});
