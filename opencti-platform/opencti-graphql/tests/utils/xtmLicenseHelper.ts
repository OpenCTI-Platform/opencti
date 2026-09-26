import forge from 'node-forge';
import { LICENSE_LEGACY_PRODUCT, LICENSE_LEGACY_TYPE, LICENSE_OID_PRODUCT, LICENSE_OID_TYPE } from '../../src/modules/settings/license-certificate';
import { LICENSE_OID_XTM_OPENCTI_IDS } from '../../src/modules/xtm/one/xtm-one-license';

// Certificates generated in memory for the tests: no Filigran key, nor any other key, is committed.

export const DAY = 24 * 60 * 60 * 1000;

// Every Filigran CA carries this subject: only the key tells them apart.
const FILIGRAN_CA_SUBJECT = [
  { name: 'commonName', value: 'Filigran CA CERT' },
  { name: 'countryName', value: 'FR' },
  { name: 'localityName', value: 'Paris' },
  { name: 'organizationName', value: 'Filigran' },
  { shortName: 'OU', value: 'Filigran' },
];

export interface TestCertificateAuthority {
  certificate: forge.pki.Certificate;
  privateKey: forge.pki.rsa.PrivateKey;
}

export const createTestCertificateAuthority = (): TestCertificateAuthority => {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = '00';
  certificate.validity.notBefore = new Date(Date.now() - DAY);
  certificate.validity.notAfter = new Date(Date.now() + 3650 * DAY);
  certificate.setSubject(FILIGRAN_CA_SUBJECT);
  certificate.setIssuer(FILIGRAN_CA_SUBJECT);
  certificate.setExtensions([{ name: 'basicConstraints', cA: true }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  return { certificate, privateKey: keys.privateKey };
};

let licenseKeys: forge.pki.rsa.KeyPair | undefined;
const getLicenseKeys = () => {
  licenseKeys ??= forge.pki.rsa.generateKeyPair({ bits: 2048 });
  return licenseKeys;
};

export interface TestXtmLicenseOptions {
  // null leaves the extension out
  product?: string | null;
  type?: string | null;
  // A list is written as JSON, a string as is
  openctiIds?: string[] | string | null;
  notBefore?: Date;
  notAfter?: Date;
  legacyOids?: boolean;
  // Wrap every extension value in a DER UTF8String
  derStrings?: boolean;
  extraExtensions?: { id: string; value: string }[];
  digest?: forge.md.MessageDigest;
}

export const createTestXtmLicense = (signer: TestCertificateAuthority, options: TestXtmLicenseOptions = {}) => {
  const encode = (text: string) => {
    const utf8 = forge.util.encodeUtf8(text);
    return options.derStrings ? String.fromCharCode(0x0c, utf8.length) + utf8 : utf8;
  };
  const product = options.product === undefined ? 'filigran xtm' : options.product;
  const type = options.type === undefined ? 'standard' : options.type;
  const openctiIds = options.openctiIds === undefined ? ['global'] : options.openctiIds;
  const extensions = [
    ...(product === null ? [] : [{ id: options.legacyOids ? LICENSE_LEGACY_PRODUCT : LICENSE_OID_PRODUCT, value: encode(product) }]),
    ...(type === null ? [] : [{ id: options.legacyOids ? LICENSE_LEGACY_TYPE : LICENSE_OID_TYPE, value: encode(type) }]),
    ...(openctiIds === null ? [] : [{
      id: LICENSE_OID_XTM_OPENCTI_IDS,
      value: encode(typeof openctiIds === 'string' ? openctiIds : JSON.stringify(openctiIds)),
    }]),
    ...(options.extraExtensions ?? []),
  ];
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = getLicenseKeys().publicKey;
  certificate.serialNumber = '00';
  certificate.validity.notBefore = options.notBefore ?? new Date(Date.now() - DAY);
  certificate.validity.notAfter = options.notAfter ?? new Date(Date.now() + 365 * DAY);
  certificate.setSubject([
    { name: 'organizationName', value: 'Test customer' },
    { shortName: 'OU', value: 'another-xtm-one-instance' },
  ]);
  certificate.setIssuer(signer.certificate.subject.attributes);
  certificate.setExtensions(extensions);
  certificate.sign(signer.privateKey, options.digest ?? forge.md.sha256.create());
  return forge.pki.certificateToPem(certificate);
};
