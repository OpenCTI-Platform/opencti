import { describe, expect, it } from 'vitest';
import { verifyIngestionAuthenticationContent } from '../../../src/modules/ingestion/ingestion-common';
import { IngestionAuthType } from '../../../src/generated/graphql';

describe('Ingestion Taxii creation validations', () => {
  it('username in input should not contains :', () => {
    expect(() => verifyIngestionAuthenticationContent(IngestionAuthType.Basic, 'user:name:password')).toThrowError('Username and password cannot have : character.');
  });

  it('valid username in input should not raise error.', () => {
    verifyIngestionAuthenticationContent(IngestionAuthType.Basic, 'user-Name:P@$$word!');
    // no expect needed since exception fail tests.
  });

  it('certificate in input should not contains :', () => {
    expect(() => verifyIngestionAuthenticationContent(IngestionAuthType.Certificate, 'aaaaaaaaaaaaa:111111111111:22222222:222222')).toThrowError('Certificate, CA and Key cannot have : character.');
  });
});
