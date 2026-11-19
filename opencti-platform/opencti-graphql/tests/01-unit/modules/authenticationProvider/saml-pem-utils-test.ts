import { describe, expect, it } from 'vitest';
import { firstSamlCertificate, joinSamlIdpCertificates, normalizeSamlPemValue, splitSamlIdpCertificates } from '../../../../src/modules/authenticationProvider/saml-pem-utils';

const PEM = '-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----';
// Same pattern as node-saml keyInfoToPem: strict RFC 7468 framing, at most one trailing newline
const STRICT_PEM_REGEX = /^-----BEGIN [A-Z ]+-----\n(?:[A-Za-z0-9+/=]+\n)+-----END [A-Z ]+-----\n?$/;

describe('normalizeSamlPemValue', () => {
  it('keeps a well-formed PEM value unchanged', () => {
    expect(normalizeSamlPemValue(PEM)).toBe(PEM);
    expect(STRICT_PEM_REGEX.test(normalizeSamlPemValue(PEM))).toBe(true);
  });

  it('removes blank lines and spaces around the header and the footer', () => {
    const pasted = `\n  ${PEM}\n\n\n  `;
    expect(STRICT_PEM_REGEX.test(pasted)).toBe(false);
    expect(normalizeSamlPemValue(pasted)).toBe(PEM);
    expect(STRICT_PEM_REGEX.test(normalizeSamlPemValue(pasted))).toBe(true);
  });

  it('converts Windows line endings', () => {
    const windows = `${PEM.replace(/\n/g, '\r\n')}\r\n\r\n`;
    expect(normalizeSamlPemValue(windows)).toBe(PEM);
  });

  it('keeps a raw base64 certificate without framing', () => {
    expect(normalizeSamlPemValue('  MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8w  \n')).toBe('MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8w');
  });

  it('returns undefined for an empty or blank value and keeps a missing value', () => {
    expect(normalizeSamlPemValue('   \n ')).toBeUndefined();
    expect(normalizeSamlPemValue(undefined)).toBeUndefined();
    expect(normalizeSamlPemValue(null)).toBeNull();
  });
});

// Self-signed EC certificates generated for these tests only
const RAW_CERT_1 = 'MIIBbDCCARKgAwIBAgIUHCxIS1jXMnd+yfKWSVf7BzHp1v4wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb3BlbmN0aS10ZXN0LWlkcDEwHhcNMjYxMTE4MTczNTEzWhcNMzYxMTE1MTczNTEzWjAcMRowGAYDVQQDDBFvcGVuY3RpLXRlc3QtaWRwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOZlR2BVqH7CjmcuVuzPO8PDnQmJipTvKkcSpTHKM+0x7kcpcAohfW4EIOoW0GlpLT5gChZ3SxNobRRn6PtWEHCjMjAwMB0GA1UdDgQWBBRyzJHxzTcDDb98AsxM5F9azSmanzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCT2Cjc2Ne870EoDjvAzQV7yQLo4wrIk+Da892IHOPUvgIgVd7fIiDC//6ZNK1TLRMSpiQU3XDjmDLH8SXg9lTbgPk=';
const RAW_CERT_2 = 'MIIBbDCCARKgAwIBAgIUTwQfJAgEFrWLChlweukInD/YJj0wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb3BlbmN0aS10ZXN0LWlkcDIwHhcNMjYxMTE4MTczNTEzWhcNMzYxMTE1MTczNTEzWjAcMRowGAYDVQQDDBFvcGVuY3RpLXRlc3QtaWRwMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFUGtT63r1WN25XOCGvegT0huwS/N2sIbxpcwJNHdLeDaT2QVRyJJ/qbO7vaYBnzkGk7095Uiaf9ulPs3VAXHJ6jMjAwMB0GA1UdDgQWBBRsTeHkNyhnA9jUPGTqKQYpj9nLuDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDVTHrQfB1FfXzjtl3jUd5G4bVzKUZgobsimoctOOj4hAIgcaIbZZrAx+5MpJMU7wCPco1LUOdARKVfpOm+jeVLftU=';
const toPem = (raw: string) => `-----BEGIN CERTIFICATE-----\n${raw.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
const PEM_CERT_1 = toPem(RAW_CERT_1);
const PEM_CERT_2 = toPem(RAW_CERT_2);

describe('joinSamlIdpCertificates', () => {
  it('keeps a single certificate unchanged', () => {
    expect(joinSamlIdpCertificates(RAW_CERT_1)).toBe(RAW_CERT_1);
    expect(joinSamlIdpCertificates([RAW_CERT_1])).toBe(RAW_CERT_1);
  });

  it('joins several raw certificates as PEM blocks in a single string', () => {
    expect(joinSamlIdpCertificates([RAW_CERT_1, RAW_CERT_2])).toBe(`${PEM_CERT_1}\n${PEM_CERT_2}`);
  });

  it('keeps the PEM certificates of a list and ignores the blank ones', () => {
    expect(joinSamlIdpCertificates([`\n${PEM_CERT_1}\r\n`, '  ', RAW_CERT_2])).toBe(`${PEM_CERT_1}\n${PEM_CERT_2}`);
    expect(joinSamlIdpCertificates([])).toBe('');
  });

  it('ignores the values of a list that are not strings', () => {
    expect(joinSamlIdpCertificates([RAW_CERT_1, 123, null, { cert: RAW_CERT_2 }])).toBe(RAW_CERT_1);
  });

  it('keeps a PEM certificate with text before it as is', () => {
    const withText = `subject=CN = idp\n${PEM_CERT_1}`;
    expect(joinSamlIdpCertificates([withText, RAW_CERT_2])).toBe(`${withText}\n${PEM_CERT_2}`);
    expect(splitSamlIdpCertificates(joinSamlIdpCertificates([withText, RAW_CERT_2]))).toEqual([PEM_CERT_1, PEM_CERT_2, 'subject=CN = idp']);
  });
});

describe('splitSamlIdpCertificates', () => {
  it('keeps a single certificate as a string', () => {
    expect(splitSamlIdpCertificates(RAW_CERT_1)).toBe(RAW_CERT_1);
    expect(splitSamlIdpCertificates(`\n${PEM_CERT_1}\n\n`)).toBe(PEM_CERT_1);
  });

  it('keeps a raw certificate wrapped on several lines as one certificate', () => {
    const wrapped = RAW_CERT_1.match(/.{1,64}/g)?.join('\n') ?? '';
    expect(splitSamlIdpCertificates(wrapped)).toBe(wrapped);
  });

  it('splits several PEM certificates into a list', () => {
    expect(splitSamlIdpCertificates(`${PEM_CERT_1}\n\n${PEM_CERT_2}\n`)).toEqual([PEM_CERT_1, PEM_CERT_2]);
  });

  it('splits a PEM certificate followed by a raw certificate', () => {
    expect(splitSamlIdpCertificates(`${PEM_CERT_1}\n${RAW_CERT_2}`)).toEqual([PEM_CERT_1, RAW_CERT_2]);
  });

  it('keeps the text outside the PEM blocks so that node-saml reports it', () => {
    expect(splitSamlIdpCertificates(`Bag Attributes\n${PEM_CERT_1}\n${PEM_CERT_2}`)).toEqual([PEM_CERT_1, PEM_CERT_2, 'Bag Attributes']);
  });

  it('gives back the certificates of a list stored by an older migration', () => {
    expect(splitSamlIdpCertificates([RAW_CERT_1, RAW_CERT_2])).toEqual([RAW_CERT_1, RAW_CERT_2]);
    expect(splitSamlIdpCertificates([RAW_CERT_1, 123])).toBe(RAW_CERT_1);
  });

  it('returns an empty string for a blank value', () => {
    expect(splitSamlIdpCertificates('  ')).toBe('');
    expect(splitSamlIdpCertificates([])).toBe('');
  });

  it('gives back the certificates joined by joinSamlIdpCertificates', () => {
    expect(splitSamlIdpCertificates(joinSamlIdpCertificates([RAW_CERT_1, RAW_CERT_2]))).toEqual([PEM_CERT_1, PEM_CERT_2]);
  });
});

describe('firstSamlCertificate', () => {
  it('keeps a single certificate unchanged and gives undefined for a missing value', () => {
    expect(firstSamlCertificate(RAW_CERT_1)).toBe(RAW_CERT_1);
    expect(firstSamlCertificate(null)).toBeUndefined();
    expect(firstSamlCertificate(undefined)).toBeUndefined();
  });

  it('keeps the first certificate of a list stored by an older migration', () => {
    expect(firstSamlCertificate(['  ', 42, `\n${PEM_CERT_1}\r\n`, PEM_CERT_2])).toBe(PEM_CERT_1);
  });

  it('returns undefined for a list without certificate', () => {
    expect(firstSamlCertificate([])).toBeUndefined();
    expect(firstSamlCertificate(['', null])).toBeUndefined();
  });
});
