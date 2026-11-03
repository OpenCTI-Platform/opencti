import { describe, expect, it } from 'vitest';
import { normalizeSamlPemValue } from '../../../../src/modules/authenticationProvider/saml-pem-utils';

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
