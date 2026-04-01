import { describe, expect, it } from 'vitest';
import { queryInitPlatformAsAnonymous } from '../../utils/testQuery';
import gql from 'graphql-tag';
import { validate as uuidValidate } from 'uuid';

describe('askSendOtp', () => {
  it('Should return a transactionId with a wrong email', async () => {
    const ASKSENDOTP_QUERY = gql`
      mutation askSendOtp($input: AskSendOtpInput!){
        askSendOtp(input: $input)
      }
    `;
    const queryResult = await queryInitPlatformAsAnonymous(ASKSENDOTP_QUERY, { input: { email: 'noResul@opencti.io' } });
    expect(uuidValidate(queryResult.data.askSendOtp)).toBeTruthy();
  });
});
