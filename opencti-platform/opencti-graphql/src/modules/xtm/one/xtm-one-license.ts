/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import forge from 'node-forge';
import { XTM_CA } from '../../../enterprise-edition/xtm_ca';
import {
  computeCiLicenseExpirationDate,
  getExtensionValue,
  GLOBAL_LICENSE_OPTION,
  LICENSE_LEGACY_CREATOR,
  LICENSE_LEGACY_PRODUCT,
  LICENSE_LEGACY_TYPE,
  LICENSE_OID_CREATOR,
  LICENSE_OID_PRODUCT,
  LICENSE_OID_TYPE,
  LICENSE_TYPE_CI,
  LICENSE_TYPE_LTS,
  LICENSE_TYPE_TRIAL,
  LICENSE_TYPES,
} from '../../settings/license-certificate';
import type { BasicStoreSettings } from '../../../types/settings';

// JSON list of the OpenCTI platform ids an XTM license sub-licenses, 'global' covering every platform.
export const LICENSE_OID_XTM_OPENCTI_IDS = '1.3.6.1.4.1.62944.50';
const XTM_LICENSE_PRODUCT = 'filigran xtm';
// Days, as XTM One counts them: not the three calendar months of OpenCTI's own license.
const XTM_LICENSE_GRACE_PERIOD = 90 * 24 * 60 * 60 * 1000;
// One PEM certificate block and nothing else, as XTM One serialises it: no chain, no key, no header.
const SINGLE_PEM_CERTIFICATE = /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----$/;
// UTF8String, PrintableString, IA5String and OCTET STRING: the DER wrappers XTM One unwraps from an extension value,
// only when their single length byte covers the rest of it. Reading a long-form length would grant what XTM One refuses.
const DER_STRING_TAGS = [0x0c, 0x13, 0x16, 0x04];
// RSASSA-PKCS1-v1_5 only, as XTM One verifies it, and never over a SHA-1 or MD5 digest.
const SIGNATURE_DIGESTS = new Map<string, () => forge.md.MessageDigest>([
  [forge.pki.oids.sha256WithRSAEncryption, () => forge.md.sha256.create()],
  [forge.pki.oids.sha384WithRSAEncryption, () => forge.md.sha384.create()],
  [forge.pki.oids.sha512WithRSAEncryption, () => forge.md.sha512.create()],
]);

export interface XtmLicenseContext {
  // The platform_id this platform registers with at XTM One.
  platformId: string;
  // Caps a ci license, exactly as for OpenCTI's own ci licenses.
  platformCreatedAt: Date | string | undefined;
  // An LTS platform needs an lts or ci license, the rule OpenCTI applies to its own licenses.
  ltsPlatform?: boolean;
  now?: Date;
}

// What the certificate says, once it grants the entitlement: displayed on the Enterprise Edition settings.
export interface XtmLicenseCertificate {
  customer: string;
  creator: string;
  platform: string;
  global: boolean;
  startDate: Date;
  // The license end date (ci cap applied), before any grace period.
  expirationDate: Date;
}

export interface XtmLicenseVerification {
  granted: boolean;
  reason: string;
  licenseType?: string;
  // End of the entitlement, grace period included.
  validUntil?: Date;
  certificate?: XtmLicenseCertificate;
}

interface XtmLicense {
  product: string | undefined;
  type: string | undefined;
  openctiIds: string[];
  customer: string;
  creator: string;
  platform: string;
  startDate: Date;
  endDate: Date;
}

type DecodedXtmLicense = { license: XtmLicense } | { refusal: string };

const readExtensionText = (certificate: forge.pki.Certificate, standardOid: string, legacyOid?: string) => {
  const value = getExtensionValue(certificate, standardOid, legacyOid);
  if (typeof value !== 'string') {
    return undefined;
  }
  const bytes = Buffer.from(value, 'binary');
  const isDerString = bytes.length > 2 && DER_STRING_TAGS.includes(bytes[0]) && bytes[1] === bytes.length - 2;
  return (isDerString ? bytes.subarray(2) : bytes).toString('utf8').trim();
};

const readPlatformIds = (text: string | undefined): string[] => {
  if (!text) {
    return [];
  }
  try {
    const ids: unknown = JSON.parse(text);
    return Array.isArray(ids) ? ids.filter((id): id is string => typeof id === 'string') : [];
  } catch {
    return [];
  }
};

// Against the pinned key itself, as XTM One does: no chain, no issuer name match, no path validation.
const isSignedByXtmCa = (certificate: forge.pki.Certificate) => {
  const createDigest = SIGNATURE_DIGESTS.get(certificate.signatureOid);
  if (!createDigest) {
    return false;
  }
  try {
    const digest = createDigest().update(forge.asn1.toDer(certificate.tbsCertificate).getBytes());
    return (XTM_CA.publicKey as forge.pki.rsa.PublicKey).verify(digest.digest().getBytes(), certificate.signature);
  } catch {
    return false;
  }
};

const decodeXtmLicense = (pem: string): DecodedXtmLicense => {
  const text = pem.trim();
  if (!SINGLE_PEM_CERTIFICATE.test(text)) {
    return { refusal: 'the XTM license is not a single PEM certificate' };
  }
  let certificate: forge.pki.Certificate;
  try {
    certificate = forge.pki.certificateFromPem(text);
  } catch {
    return { refusal: 'the XTM license certificate cannot be parsed' };
  }
  if (!isSignedByXtmCa(certificate)) {
    return { refusal: 'the XTM license is not signed by the Filigran XTM CA' };
  }
  const extensionIds = certificate.extensions.map((extension) => extension.id);
  if (new Set(extensionIds).size !== extensionIds.length) {
    return { refusal: 'the XTM license repeats a certificate extension' };
  }
  return {
    license: {
      product: readExtensionText(certificate, LICENSE_OID_PRODUCT, LICENSE_LEGACY_PRODUCT),
      type: readExtensionText(certificate, LICENSE_OID_TYPE, LICENSE_LEGACY_TYPE),
      openctiIds: readPlatformIds(readExtensionText(certificate, LICENSE_OID_XTM_OPENCTI_IDS)),
      // Displayed only: like XTM One, nothing is decided on the subject.
      customer: certificate.subject.getField('O')?.value ?? 'Unknown',
      platform: certificate.subject.getField('OU')?.value ?? GLOBAL_LICENSE_OPTION,
      creator: readExtensionText(certificate, LICENSE_OID_CREATOR, LICENSE_LEGACY_CREATOR) || 'Unknown',
      startDate: certificate.validity.notBefore,
      endDate: certificate.validity.notAfter,
    },
  };
};

// Heartbeats keep returning the same certificate: its signature is only verified once.
let lastDecoded: { pem: string; decoded: DecodedXtmLicense } | undefined;
const decodeXtmLicenseOnce = (pem: string) => {
  if (lastDecoded?.pem !== pem) {
    lastDecoded = { pem, decoded: decodeXtmLicense(pem) };
  }
  return lastDecoded.decoded;
};

const verifyValidityDates = (license: XtmLicense, licenseType: string, context: XtmLicenseContext): XtmLicenseVerification => {
  const now = context.now ?? new Date();
  const grant = (expirationDate: Date, validUntil: Date): XtmLicenseVerification => ({
    granted: true,
    reason: 'the XTM license sub-licenses this OpenCTI platform',
    licenseType,
    validUntil,
    certificate: {
      customer: license.customer,
      creator: license.creator,
      platform: license.platform,
      global: license.openctiIds.includes(GLOBAL_LICENSE_OPTION),
      startDate: license.startDate,
      expirationDate,
    },
  });
  if (licenseType === LICENSE_TYPE_TRIAL || licenseType === LICENSE_TYPE_CI) {
    let { endDate } = license;
    if (licenseType === LICENSE_TYPE_CI) {
      const platformCreatedAt = context.platformCreatedAt ? new Date(context.platformCreatedAt) : undefined;
      if (!platformCreatedAt || Number.isNaN(platformCreatedAt.getTime())) {
        return { granted: false, reason: 'the ci XTM license cannot be dated without the platform creation date', licenseType };
      }
      endDate = computeCiLicenseExpirationDate(platformCreatedAt, license.startDate);
    }
    if (now < license.startDate) {
      return { granted: false, reason: `the ${licenseType} XTM license is not valid yet`, licenseType };
    }
    if (now > endDate) {
      return { granted: false, reason: `the ${licenseType} XTM license has expired`, licenseType };
    }
    return grant(endDate, endDate);
  }
  // The grace period also covers a license whose start date is still ahead: XTM One does not enforce it for these types.
  const validUntil = new Date(license.endDate.getTime() + XTM_LICENSE_GRACE_PERIOD);
  if (now >= validUntil) {
    return { granted: false, reason: 'the XTM license has expired and its 90-day grace period is over', licenseType };
  }
  return grant(license.endDate, validUntil);
};

/**
 * Whether an XTM license certificate grants this platform the XTM One entitlement, by the checks XTM One itself runs
 * before sub-licensing a platform: the signature of the pinned XTM CA, the `filigran xtm` product, a known license
 * type, this platform or `global` in the OpenCTI sub-license, and XTM One's validity dates.
 */
export const verifyXtmLicenseProof = (pem: unknown, context: XtmLicenseContext): XtmLicenseVerification => {
  if (pem === undefined || pem === null || pem === '') {
    return { granted: false, reason: 'XTM One returned no XTM license certificate' };
  }
  if (typeof pem !== 'string') {
    return { granted: false, reason: 'the XTM license is not a single PEM certificate' };
  }
  const decoded = decodeXtmLicenseOnce(pem);
  if ('refusal' in decoded) {
    return { granted: false, reason: decoded.refusal };
  }
  const { license } = decoded;
  if (license.product !== XTM_LICENSE_PRODUCT) {
    return { granted: false, reason: 'the certificate is not an XTM license' };
  }
  const licenseType = license.type || LICENSE_TYPE_TRIAL;
  if (!LICENSE_TYPES.includes(licenseType)) {
    return { granted: false, reason: 'the XTM license type is unknown' };
  }
  if (context.ltsPlatform && licenseType !== LICENSE_TYPE_LTS && licenseType !== LICENSE_TYPE_CI) {
    return { granted: false, reason: `an LTS platform needs an lts or ci license, the XTM license is ${licenseType}`, licenseType };
  }
  if (!license.openctiIds.includes(GLOBAL_LICENSE_OPTION) && !license.openctiIds.includes(context.platformId)) {
    return { granted: false, reason: 'the XTM license does not sub-license this OpenCTI platform', licenseType };
  }
  return verifyValidityDates(license, licenseType, context);
};

export const buildXtmLicenseContext = (settings: Pick<BasicStoreSettings, 'internal_id' | 'id' | 'created_at'>, ltsPlatform: boolean): XtmLicenseContext => ({
  platformId: settings.internal_id || settings.id,
  platformCreatedAt: settings.created_at,
  ltsPlatform,
});

// The XTM license of the last registration answer this node read: the one proof of the XTM license path. Kept up to
// date by xtm-one.ts, read synchronously by the Enterprise Edition resolution, which verifies it again on every read.
let currentXtmLicenseProof: string | null = null;
export const setCurrentXtmLicenseProof = (pem: unknown) => {
  currentXtmLicenseProof = typeof pem === 'string' && pem !== '' ? pem : null;
};
export const getCurrentXtmLicenseProof = () => currentXtmLicenseProof;
