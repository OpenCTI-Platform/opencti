import { describe, expect, it } from 'vitest';
import { createUnauthenticatedClient, executeInternalQuery } from '../../utils/testQuery';
import gql from 'graphql-tag';
import { validate as uuidValidate } from 'uuid';
import { print } from 'graphql/index';

describe('askSendOtp', () => {
  it('Should return a transactionId with a wrong email', async () => {
    const ASKSENDOTP_QUERY = gql`
      mutation askSendOtp($input: AskSendOtpInput!){
        askSendOtp(input: $input)
      }
    `;
    const anonymous = createUnauthenticatedClient();
    const queryResult = await executeInternalQuery(anonymous, print(ASKSENDOTP_QUERY), { input: { email: 'noResul@opencti.io' } });
    expect(uuidValidate(queryResult.data.askSendOtp)).toBeTruthy();
  });
});