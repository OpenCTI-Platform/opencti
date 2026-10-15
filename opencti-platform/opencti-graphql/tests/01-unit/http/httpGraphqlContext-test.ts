import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createGraphqlContext } from '../../../src/http/httpGraphqlContext';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';
import { isWorkAlive } from '../../../src/domain/work';
import { isVerifiedFormSubmission } from '../../../src/modules/form/form-submission-context';

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({ createAuthenticatedContext: vi.fn() }));
vi.mock('../../../src/http/httpServer-draft', () => ({ checkDraftInContext: vi.fn() }));
vi.mock('../../../src/domain/work', () => ({ isWorkAlive: vi.fn() }));
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
    expect(isWorkAlive).not.toHaveBeenCalled();
    expect(isVerifiedFormSubmission).not.toHaveBeenCalled();
    expect(checkDraftInContext).toHaveBeenCalledOnce();
  });

  it('should refuse a request bound to a work that is not alive, without verifying anything', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: { id: 'user-1' }, workId: 'work-1' } as any);
    vi.mocked(isWorkAlive).mockResolvedValue(false);
    await expect(createGraphqlContext(req, res)).rejects.toThrow();
    expect(isVerifiedFormSubmission).not.toHaveBeenCalled();
    expect(checkDraftInContext).not.toHaveBeenCalled();
  });

  it('should flag a live work whose import is verified as a form submission', async () => {
    const executeContext = { user: { id: 'user-1' }, workId: 'work-1' };
    vi.mocked(createAuthenticatedContext).mockResolvedValue(executeContext as any);
    vi.mocked(isWorkAlive).mockResolvedValue(true);
    vi.mocked(isVerifiedFormSubmission).mockResolvedValue(true);
    const context: any = await createGraphqlContext(req, res);
    expect(isVerifiedFormSubmission).toHaveBeenCalledWith(executeContext);
    expect(context.form_submission).toBe(true);
  });

  it('should not flag a live work that is not a verified form submission', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: { id: 'user-1' }, workId: 'work-1' } as any);
    vi.mocked(isWorkAlive).mockResolvedValue(true);
    vi.mocked(isVerifiedFormSubmission).mockResolvedValue(false);
    const context: any = await createGraphqlContext(req, res);
    expect(context.form_submission).toBe(false);
    expect(checkDraftInContext).toHaveBeenCalledOnce();
  });
});
