/*
Copyright (c) 2021-2024 Filigran SAS

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
import conf from '../../config/conf';

const GLOBAL_LICENSE_OPTION = 'global';
export const LICENSE_OPTION_TRIAL = 'trial';

// https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
// 62944 - Filigran
export const LICENSE_OPTION_TYPE = '6.2.9.4.4.10';
export const LICENSE_OPTION_PRODUCT = '6.2.9.4.4.20';
export const LICENSE_OPTION_CREATOR = '6.2.9.4.4.30';

const getExtensionValue = (clientCrt, extension) => {
  return clientCrt.extensions.find((ext) => ext.id === extension)?.value;
};

export const getEnterpriseEditionInfoFromPem = (platformInstanceId, rawPem) => {
  const pemFromConfig = conf.get('app:enterprise_edition_license');
  const pem = isNotEmptyField(pemFromConfig) ? pemFromConfig : rawPem;
  const license_enterprise = isNotEmptyField(pem);
  if (isNotEmptyField(pem)) {
    try {
      const clientCrt = forge.pki.certificateFromPem(pem);
      const license_valid_cert = OPENCTI_CA.verify(clientCrt);
      const license_type = getExtensionValue(clientCrt, LICENSE_OPTION_TYPE);
      const license_creator = getExtensionValue(clientCrt, LICENSE_OPTION_CREATOR);
      const valid_product = getExtensionValue(clientCrt, LICENSE_OPTION_PRODUCT) === 'opencti';
      const license_customer = clientCrt.subject.getField('O').value;
      const license_platform = clientCrt.subject.getField('OU').value;
      const license_platform_match = valid_product && (license_platform === GLOBAL_LICENSE_OPTION || platformInstanceId === license_platform);
      const license_global = license_platform === GLOBAL_LICENSE_OPTION;
      const license_expired = new Date() > clientCrt.validity.notAfter || new Date() < clientCrt.validity.notBefore;
      const license_start_date = clientCrt.validity.notBefore;
      const license_expiration_date = clientCrt.validity.notAfter;
      const license_expiration_prevention = license_type !== LICENSE_OPTION_TRIAL && utcDate(clientCrt.validity.notAfter).diff(now(), 'months') < 3;
      let license_validated = license_valid_cert && license_platform_match;
      let license_extra_expiration = false;
      let license_extra_expiration_days = 0;
      if (license_validated && license_expired) {
        // If trial license, deactivation for expiration is direct
        if (license_type !== LICENSE_OPTION_TRIAL) {
          // If standard or lts license, a 3 months safe period is granted
          const license_extra_expiration_date = utcDate(clientCrt.validity.notBefore).add(3, 'months');
          license_extra_expiration_days = license_extra_expiration_date.diff(utcDate(), 'days');
          license_extra_expiration = new Date() < license_extra_expiration_date.toDate();
          license_validated = license_extra_expiration;
        }
      }
      return {
        license_enterprise, // If EE activated
        license_by_configuration: isNotEmptyField(pemFromConfig),
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
    license_by_configuration: isNotEmptyField(pemFromConfig),
    license_valid_cert: false,
    license_extra_expiration: false,
    license_extra_expiration_days: 0,
    license_customer: 'invalid',
    license_expired: true,
    license_expiration_date: new Date(),
    license_start_date: new Date(),
    license_platform: 'invalid',
    license_type: 'trial',
    license_expiration_prevention: false,
    license_platform_match: true,
    license_creator: 'Unknown',
    license_global: false,
  };
};

export const getEnterpriseEditionInfo = (settings) => {
  return getEnterpriseEditionInfoFromPem(settings.internal_id, settings.enterprise_license);
};
