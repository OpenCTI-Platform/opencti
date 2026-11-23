import { describe, expect, it, vi } from 'vitest';
import type Express from 'express';
import { errorConverter } from '../../../src/http/httpRollingFeed';
import { DatabaseError, ForbiddenAccess } from '../../../src/config/errors';
import { logApp } from '../../../src/config/conf';

const mockRes = (requestId = 'req-1') => ({ locals: { requestId } } as unknown as Express.Response);

describe('httpRollingFeed: errorConverter', () => {
  it('should keep the status, code and message of a caller error', () => {
    const converted = errorConverter(ForbiddenAccess(), mockRes());
    expect(converted).toEqual(expect.objectContaining({
      title: 'You are not allowed to do this.',
      request_id: 'req-1',
      error_code: 'FORBIDDEN_ACCESS',
      http_status: 403,
    }));
    expect(converted).toHaveProperty('details', {});
  });

  it('should hide and log a platform failure', () => {
    const errorSpy = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    const converted = errorConverter(DatabaseError('connect ECONNREFUSED 10.0.0.5:9200'), mockRes());
    expect(converted).toEqual({ title: 'An unexpected error occurred', request_id: 'req-1', http_status: 500 });
    expect(errorSpy).toHaveBeenCalledWith('CSV feed request failed', expect.objectContaining({ request_id: 'req-1' }));
    errorSpy.mockRestore();
  });

  it('should answer 500 for an untyped error', () => {
    vi.spyOn(logApp, 'error').mockImplementation(() => {});
    expect(errorConverter(new Error('boom'), mockRes())).toEqual(expect.objectContaining({ title: 'An unexpected error occurred', http_status: 500 }));
    vi.restoreAllMocks();
  });
});
