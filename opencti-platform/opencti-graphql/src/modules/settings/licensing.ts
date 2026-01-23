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
import { isNotEmptyField } from '../../database/utils';
import { now, utcDate } from '../../utils/format';
import { OPENCTI_CA } from '../../enterprise-edition/opencti_ca';
import conf, { PLATFORM_VERSION } from '../../config/conf';
import type { BasicStoreSettings } from '../../types/settings';
import type { PlatformEe } from '../../generated/graphql';

const GLOBAL_LICENSE_OPTION = 'global';
const LICENSE_TYPE_STANDARD = 'standard';
const LICENSE_TYPE_NFR = 'nfr';
const LICENSE_TYPE_TRIAL = 'trial';
const LICENSE_TYPE_LTS = 'lts';
const LICENSE_TYPE_CI = 'ci';
const LICENSE_TYPES = [
  LICENSE_TYPE_STANDARD,
  LICENSE_TYPE_NFR,
  LICENSE_TYPE_TRIAL,
  LICENSE_TYPE_LTS,
  LICENSE_TYPE_CI,
];
export const IS_LTS_PLATFORM = PLATFORM_VERSION.includes('lts');

// https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
// 62944 - Filigran
export const LICENSE_OID_TYPE = '1.3.6.1.4.1.62944.10';
export const LICENSE_OID_PRODUCT = '1.3.6.1.4.1.62944.20';
export const LICENSE_OID_CREATOR = '1.3.6.1.4.1.62944.30';
// Legacy OIDs
export const LICENSE_LEGACY_TYPE = '6.2.9.4.4.10';
export const LICENSE_LEGACY_PRODUCT = '6.2.9.4.4.20';
export const LICENSE_LEGACY_CREATOR = '6.2.9.4.4.30';

const getExtensionValue = (clientCrt: forge.pki.Certificate, standardOid: string, legacyOid: string) => {
  const extStandard = clientCrt.extensions.find((ext) => ext.id === standardOid);
  if (extStandard) {
    return extStandard.value;
  }
  return clientCrt.extensions.find((ext) => ext.id === legacyOid)?.value;
};

export const getEnterpriseEditionActivePem = (settings: BasicStoreSettings) => {
  const pemFromConfig: string | undefined = conf.get('app:enterprise_edition_license');
  const licenseByConfiguration = isNotEmptyField(pemFromConfig);
  return {
    licenseByConfiguration,
    pem: licenseByConfiguration ? pemFromConfig : settings.enterprise_license,
  };
};

export const decodeLicensePem = (settings: BasicStoreSettings, overridePem?: string): PlatformEe => {
  const currentDate = new Date();
  const { pem, licenseByConfiguration } = overridePem ? {
    pem: overridePem,
    licenseByConfiguration: false,
  } : getEnterpriseEditionActivePem(settings);
  const license_enterprise = pem !== undefined && isNotEmptyField(pem);
  if (license_enterprise) {
    try {
      const clientCrt = forge.pki.certificateFromPem(pem);
      const license_valid_cert = OPENCTI_CA.verify(clientCrt);
      const license_type = getExtensionValue(clientCrt, LICENSE_OID_TYPE, LICENSE_LEGACY_TYPE);
      const valid_type = LICENSE_TYPES.includes(license_type) && (!IS_LTS_PLATFORM || license_type === LICENSE_TYPE_LTS);
      const license_creator = getExtensionValue(clientCrt, LICENSE_OID_CREATOR, LICENSE_LEGACY_CREATOR);
      const valid_product = getExtensionValue(clientCrt, LICENSE_OID_PRODUCT, LICENSE_LEGACY_PRODUCT) === 'opencti';
      const license_customer = clientCrt.subject.getField('O').value;
      const license_platform = clientCrt.subject.getField('OU').value;
      const license_global = license_platform === GLOBAL_LICENSE_OPTION;
      const license_platform_match = valid_product && valid_type && (license_global || settings.internal_id === license_platform);
      const license_start_date = clientCrt.validity.notBefore;
      const license_expiration_date = clientCrt.validity.notAfter;
      if (license_type === LICENSE_TYPE_CI) {
        // settings.created_at is sometime a string...
        const createdAt = new Date(settings.created_at);
        const ciPlatformEndDate = new Date(createdAt.getTime() + 2700000);
        const certEndDate = new Date(license_start_date.getTime() + 31536000000);
        const expirationDate = ciPlatformEndDate < certEndDate ? ciPlatformEndDate : certEndDate;
        license_expiration_date.setTime(expirationDate.getTime());
      }
      const license_expired = currentDate > license_expiration_date || currentDate < license_start_date;
      const license_expiration_prevention = license_type !== LICENSE_TYPE_TRIAL && license_type !== LICENSE_TYPE_CI && utcDate(license_expiration_date).diff(now(), 'months') < 3;
      let license_validated = license_valid_cert && license_platform_match;
      let license_extra_expiration = false;
      let license_extra_expiration_days = 0;
      if (license_validated && license_expired) {
        // If trial or CI license, deactivation for expiration is direct
        if (license_type !== LICENSE_TYPE_TRIAL && license_type !== LICENSE_TYPE_CI) {
          // If standard or lts license, a 3 months safe period is granted
          const license_extra_expiration_date = utcDate(license_expiration_date).add(3, 'months');
          license_extra_expiration_days = license_extra_expiration_date.diff(utcDate(), 'days');
          license_extra_expiration = currentDate < license_extra_expiration_date.toDate();
          license_validated = license_extra_expiration;
        } else {
          license_validated = false;
        }
      }
      return {
        license_enterprise, // If EE activated
        license_by_configuration: licenseByConfiguration,
        license_validated, // If EE license is ok (identifier, dates, ...)
        license_valid_cert,
        license_customer,
        license_expired,
        license_extra_expiration,
        license_extra_expiration_days,
        license_expiration_date,
        license_start_date,
        license_expiration_prevention,
        license_platform,
        license_type,
        license_platform_match,
        license_creator,
        license_global,
      };
    } catch {
      // Nothing to do here
    }
  }
  return {
    license_enterprise,
    license_validated: false,
    license_by_configuration: licenseByConfiguration,
    license_valid_cert: false,
    license_extra_expiration: false,
    license_extra_expiration_days: 0,
    license_customer: 'invalid',
    license_expired: true,
    license_expiration_date: currentDate,
    license_start_date: currentDate,
    license_platform: 'invalid',
    license_type: 'trial',
    license_expiration_prevention: false,
    license_platform_match: true,
    license_creator: 'Unknown',
    license_global: false,
  };
};

let cachedLicence: PlatformEe | undefined = undefined;
let cachedPem: string | undefined = undefined;
let cacheExpiration: number | undefined = undefined;

export const getEnterpriseEditionInfo = (settings: BasicStoreSettings) => {
  const { pem } = getEnterpriseEditionActivePem(settings);
  const now = Date.now();
  if (cachedLicence === undefined || cachedPem !== pem || (cacheExpiration !== undefined && now > cacheExpiration)) {
    cachedLicence = decodeLicensePem(settings);
    cachedPem = pem;
    cacheExpiration = now + 300000; // Cache for 5 minutes
  }
  return cachedLicence;
};
