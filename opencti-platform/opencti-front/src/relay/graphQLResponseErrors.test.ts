import { describe, expect, it } from 'vitest';
import { getGraphQLResponseErrors, getGraphQLResponseErrorsMessage } from './graphQLResponseErrors';

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

describe('getGraphQLResponseErrorsMessage', () => {
  // As thrown by the network layer: its message wraps the errors of the response
  const relayError = (errors: { message?: string }[]) => Object.assign(
    new Error('Relay request for `xAddMutation` failed by the following reasons: ...'),
    { res: { errors } },
  );

  it('gives only the messages of the response errors', () => {
    expect(getGraphQLResponseErrorsMessage(relayError([{ message: 'Observable is not correctly formatted' }])))
      .toEqual('Observable is not correctly formatted');
    expect(getGraphQLResponseErrorsMessage(relayError([{ message: 'Refused' }, {}, { message: 'Forbidden' }])))
      .toEqual('Refused Forbidden');
  });

  it('gives the error own message when the response has no error message', () => {
    expect(getGraphQLResponseErrorsMessage(new Error('Network error'))).toEqual('Network error');
    expect(getGraphQLResponseErrorsMessage(relayError([{}])))
      .toEqual('Relay request for `xAddMutation` failed by the following reasons: ...');
  });
});
