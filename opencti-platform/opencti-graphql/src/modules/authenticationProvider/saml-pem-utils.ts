// node-saml validates PEM keys and certificates against a strict RFC 7468 pattern:
// a blank line before the BEGIN header or more than one newline after the END footer
// makes the value fail validation, and the provider then fails to start with no error in the UI.
// Copy-paste artifacts (leading/trailing blank lines, spaces, Windows line endings) are removed here.
export const normalizeSamlPemValue = <T extends string | null | undefined>(value: T): T => {
  if (typeof value !== 'string') {
    return value;
  }
  const normalized = value.replace(/\r\n?/g, '\n').trim();
  return (normalized.length > 0 ? normalized : undefined) as T;
};

const PEM_CERTIFICATE_REGEX = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

// A value that already holds a PEM block is kept as is, with any text around it, so that node-saml reports that text.
const toPemCertificate = (value: string): string => {
  if (value.includes('-----BEGIN')) {
    return value;
  }
  const lines = value.replace(/\s+/g, '').match(/.{1,64}/g) ?? [];
  return ['-----BEGIN CERTIFICATE-----', ...lines, '-----END CERTIFICATE-----'].join('\n');
};

// Values from a YAML or JSON list are not checked: anything that is not a non-blank string is ignored.
export const cleanSamlCertificates = (values: unknown[]): string[] => {
  return values
    .filter((value): value is string => typeof value === 'string')
    .map((value) => normalizeSamlPemValue(value))
    .filter((value): value is string => !!value);
};

// Text left outside the PEM blocks is kept, so that node-saml reports it instead of it being silently dropped.
const splitCertificateText = (value: string): string[] => {
  const normalized = normalizeSamlPemValue(value);
  if (!normalized) {
    return [];
  }
  const blocks = normalized.match(PEM_CERTIFICATE_REGEX) ?? [];
  const rest = normalized.replace(PEM_CERTIFICATE_REGEX, '').trim();
  return rest.length > 0 ? [...blocks, rest] : blocks;
};

// An IdP can publish several certificates (certificate rotation), and node-saml accepts a list.
// idp_certificate is a String in the GraphQL schema, so several certificates are stored as PEM blocks in a single string.
export const joinSamlIdpCertificates = (value: string | unknown[]): string => {
  if (!Array.isArray(value)) {
    return value;
  }
  const certificates = cleanSamlCertificates(value);
  if (certificates.length <= 1) {
    return certificates[0] ?? '';
  }
  return certificates.map(toPemCertificate).join('\n');
};

// Gives node-saml one certificate, or the list when several PEM certificates are stored.
// A list can also come from a provider migrated before the certificates were joined.
// Without certificate, node-saml gets an empty string and reports that idpCert is required.
export const splitSamlIdpCertificates = (value: string | unknown[]): string | string[] => {
  const certificates = Array.isArray(value) ? cleanSamlCertificates(value) : splitCertificateText(value);
  return certificates.length > 1 ? certificates : (certificates[0] ?? '');
};

// signing_cert and decryption_cert hold one certificate of the platform itself: node-saml's publicCert option takes a single one.
// A list can come from a provider migrated before #20166, only its first certificate is used.
export const firstSamlCertificate = (value: string | unknown[] | null | undefined): string | undefined => {
  return (Array.isArray(value) ? cleanSamlCertificates(value)[0] : value) ?? undefined;
};
