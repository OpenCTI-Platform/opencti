import { describe, expect, it } from 'vitest';
import { SAML } from '@node-saml/passport-saml';
import { buildSAMLOptions } from '../../../../src/modules/authenticationProvider/provider-saml';
import authenticationProviderResolver from '../../../../src/modules/authenticationProvider/authenticationProvider-resolver';
import type { SamlStoreConfiguration, SecretProvider } from '../../../../src/modules/authenticationProvider/authenticationProvider-types';
import { joinSamlIdpCertificates } from '../../../../src/modules/authenticationProvider/saml-pem-utils';

// Self-signed EC certificates generated for these tests only
const RAW_CERT_1 = 'MIIBbDCCARKgAwIBAgIUHCxIS1jXMnd+yfKWSVf7BzHp1v4wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb3BlbmN0aS10ZXN0LWlkcDEwHhcNMjYxMTE4MTczNTEzWhcNMzYxMTE1MTczNTEzWjAcMRowGAYDVQQDDBFvcGVuY3RpLXRlc3QtaWRwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOZlR2BVqH7CjmcuVuzPO8PDnQmJipTvKkcSpTHKM+0x7kcpcAohfW4EIOoW0GlpLT5gChZ3SxNobRRn6PtWEHCjMjAwMB0GA1UdDgQWBBRyzJHxzTcDDb98AsxM5F9azSmanzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCT2Cjc2Ne870EoDjvAzQV7yQLo4wrIk+Da892IHOPUvgIgVd7fIiDC//6ZNK1TLRMSpiQU3XDjmDLH8SXg9lTbgPk=';
const RAW_CERT_2 = 'MIIBbDCCARKgAwIBAgIUTwQfJAgEFrWLChlweukInD/YJj0wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb3BlbmN0aS10ZXN0LWlkcDIwHhcNMjYxMTE4MTczNTEzWhcNMzYxMTE1MTczNTEzWjAcMRowGAYDVQQDDBFvcGVuY3RpLXRlc3QtaWRwMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFUGtT63r1WN25XOCGvegT0huwS/N2sIbxpcwJNHdLeDaT2QVRyJJ/qbO7vaYBnzkGk7095Uiaf9ulPs3VAXHJ6jMjAwMB0GA1UdDgQWBBRsTeHkNyhnA9jUPGTqKQYpj9nLuDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDVTHrQfB1FfXzjtl3jUd5G4bVzKUZgobsimoctOOj4hAIgcaIbZZrAx+5MpJMU7wCPco1LUOdARKVfpOm+jeVLftU=';
const toPem = (raw: string) => `-----BEGIN CERTIFICATE-----\n${raw.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;

const secretsProvider: SecretProvider = {
  optional: async () => undefined,
  mandatory: async () => '',
};

const samlConfiguration = (idp_certificate: string | string[]) => ({
  issuer: 'opencti',
  entry_point: 'https://idp.example.com/sso',
  idp_certificate,
  extra_conf: [],
}) as unknown as SamlStoreConfiguration;

const meta = { name: 'SAML', identifier: 'saml' };

// Reads the IdP certificates the way node-saml does before checking a signature
class SamlCertificatesReader extends SAML {
  readCertificates() {
    return this.getKeyInfosAsPem();
  }
}
const readCertificates = async (idp_certificate: string | string[]) => {
  const options = await buildSAMLOptions(meta, samlConfiguration(idp_certificate), secretsProvider);
  return new SamlCertificatesReader(options).readCertificates();
};

describe('buildSAMLOptions', () => {
  it('gives node-saml a single IdP certificate as a string', async () => {
    const options = await buildSAMLOptions(meta, samlConfiguration(RAW_CERT_1), secretsProvider);
    expect(options.idpCert).toBe(RAW_CERT_1);
  });

  it('gives node-saml the list of IdP certificates stored as PEM blocks', async () => {
    const stored = `${toPem(RAW_CERT_1)}\n${toPem(RAW_CERT_2)}`;
    const options = await buildSAMLOptions(meta, samlConfiguration(stored), secretsProvider);
    expect(options.idpCert).toEqual([toPem(RAW_CERT_1), toPem(RAW_CERT_2)]);
  });

  it('gives node-saml the list of IdP certificates stored as a list by an older migration', async () => {
    const options = await buildSAMLOptions(meta, samlConfiguration([RAW_CERT_1, RAW_CERT_2]), secretsProvider);
    expect(options.idpCert).toEqual([RAW_CERT_1, RAW_CERT_2]);
  });
});

describe('IdP certificates read by node-saml', () => {
  it('reads every certificate joined by the migration', async () => {
    const certificates = await readCertificates(joinSamlIdpCertificates([RAW_CERT_1, toPem(RAW_CERT_2)]));
    expect(certificates).toEqual([`${toPem(RAW_CERT_1)}\n`, `${toPem(RAW_CERT_2)}\n`]);
  });

  it('reads every certificate of a list stored by an older migration', async () => {
    expect(await readCertificates([RAW_CERT_1, RAW_CERT_2])).toHaveLength(2);
  });

  it('reports the text left outside the certificates', async () => {
    const stored = joinSamlIdpCertificates([`subject=CN = idp\n${toPem(RAW_CERT_1)}`, RAW_CERT_2]);
    await expect(readCertificates(stored)).rejects.toThrow('idpCert[2] is neither valid PEM nor a valid Base64 certificate');
  });
});

describe('SamlConfiguration.idp_certificate resolver', () => {
  const resolveIdpCertificate = authenticationProviderResolver.SamlConfiguration?.idp_certificate as (parent: unknown) => string;

  it('returns a stored certificate unchanged', () => {
    expect(resolveIdpCertificate(samlConfiguration(RAW_CERT_1))).toBe(RAW_CERT_1);
  });

  it('returns a list stored by an older migration as PEM blocks in a single string', () => {
    expect(resolveIdpCertificate(samlConfiguration([RAW_CERT_1, RAW_CERT_2]))).toBe(`${toPem(RAW_CERT_1)}\n${toPem(RAW_CERT_2)}`);
  });
});
