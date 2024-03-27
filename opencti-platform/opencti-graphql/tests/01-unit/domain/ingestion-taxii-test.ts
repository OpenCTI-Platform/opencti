import { describe, expect, it } from 'vitest';
import { verifyTaxiiAuthenticationContent } from '../../../src/modules/ingestion/ingestion-taxii-domain';
import { TaxiiAuthType } from '../../../src/generated/graphql';

describe('Ingestion Taxii creation validations', () => {
  it('username in input should not contains :', () => {
    expect(() => verifyTaxiiAuthenticationContent(TaxiiAuthType.Basic, 'user:name:password')).toThrowError('Username and password cannot have : character.');
  });

  it('valid username in input should not raise error.', () => {
    verifyTaxiiAuthenticationContent(TaxiiAuthType.Basic, 'user-Name:P@$$word!');
    // no expect needed since exception fail tests.
  });

  it('certificate in input should not contains :', () => {
    expect(() => verifyTaxiiAuthenticationContent(TaxiiAuthType.Certificate, 'aaaaaaaaaaaaa:111111111111:22222222:222222')).toThrowError('Certificate, CA and Key cannot have : character.');
  });
});
