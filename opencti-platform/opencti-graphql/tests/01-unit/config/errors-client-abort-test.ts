import { describe, expect, it } from 'vitest';
import { AbortError } from 'node-fetch';
import { errors as openSearchErrors } from '@opensearch-project/opensearch';
import { ClientAbortError, DatabaseError, isClientAbort, UnsupportedError } from '../../../src/config/errors';

describe('isClientAbort', () => {
  it('should recognize the ClientAbortError an engine abort is wrapped into', () => {
    expect(isClientAbort(ClientAbortError('Fail to execute engine pagination'))).toBe(true);
  });

  it('should recognize the raw abort errors of both engine clients', () => {
    expect(isClientAbort(new AbortError('The http call was aborted before el request started.'))).toBe(true);
    expect(isClientAbort(new openSearchErrors.RequestAbortedError('Request aborted'))).toBe(true);
  });

  it('should not recognize genuine failures', () => {
    expect(isClientAbort(DatabaseError('Fail to execute engine pagination', { cause: new AbortError('aborted') }))).toBe(false);
    expect(isClientAbort(UnsupportedError('Recovery mode is only possible with a start date.'))).toBe(false);
    expect(isClientAbort(new Error('engine unavailable'))).toBe(false);
    expect(isClientAbort({ message: 'timeout' })).toBe(false);
    expect(isClientAbort(undefined)).toBe(false);
  });
});
