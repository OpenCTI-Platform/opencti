import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { authenticateUserFromRequest } from '../../../src/modules/user/user-domain';

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn().mockResolvedValue({ otp_mandatory: false }),
}));

vi.mock('../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/user/user-domain')>()),
  authenticateUserFromRequest: vi.fn(),
}));

const buildRequest = (headers: Record<string, string> = {}) => ({
  headers,
  header: (name: string) => headers[name],
  ip: '127.0.0.1',
}) as any;

describe('createAuthenticatedContext', () => {
  beforeEach(() => {
    vi.mocked(authenticateUserFromRequest).mockReset();
  });

  it('should keep who authenticated when the worker impersonates an applicant', async () => {
    // internalAuthenticateUser swaps the applicant in and records the owner of the credential in the origin
    const applicant = { id: 'applicant-1', capabilities: [], origin: { real_authentication_id: 'worker-1' } };
    vi.mocked(authenticateUserFromRequest).mockResolvedValue(applicant as any);

    const context = await createAuthenticatedContext(buildRequest({ 'opencti-applicant-id': 'applicant-1', 'opencti-work-id': 'work-1' }), {}, 'api');

    expect(context.user?.id).toBe('applicant-1');
    expect(context.workId).toBe('work-1');
    // the origin of the context user is rebuilt, the information must survive in the context itself
    expect(context.real_authentication_id).toBe('worker-1');
  });

  it('should not report an impersonation for a plain authentication', async () => {
    vi.mocked(authenticateUserFromRequest).mockResolvedValue({ id: 'user-1', capabilities: [], origin: {} } as any);

    const context = await createAuthenticatedContext(buildRequest(), {}, 'api');

    expect(context.real_authentication_id).toBeUndefined();
  });
});
