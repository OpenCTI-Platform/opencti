import { describe, expect, it } from 'vitest';
import { getGraphQLResponseErrors } from './graphQLResponseErrors';

describe('getGraphQLResponseErrors', () => {
  const refused = { message: 'Refused', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_large' } } };
  const forbidden = { message: 'Forbidden', extensions: { code: 'FORBIDDEN_ACCESS' } };

  it('reads the errors of the response, on the error and on its data', () => {
    expect(getGraphQLResponseErrors({ res: { errors: [refused] } })).toEqual([refused]);
    expect(getGraphQLResponseErrors({ data: { res: { errors: [forbidden] } } })).toEqual([forbidden]);
    expect(getGraphQLResponseErrors({ res: { errors: [refused] }, data: { res: { errors: [forbidden] } } })).toEqual([refused, forbidden]);
  });

  it('reads none for any other error', () => {
    expect(getGraphQLResponseErrors(new Error('Network error'))).toEqual([]);
    expect(getGraphQLResponseErrors({ res: {} })).toEqual([]);
    expect(getGraphQLResponseErrors(null)).toEqual([]);
    expect(getGraphQLResponseErrors(undefined)).toEqual([]);
  });
});
