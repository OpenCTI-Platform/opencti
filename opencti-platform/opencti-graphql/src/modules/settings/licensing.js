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

const GLOBAL_LICENSE_OPTION = 'global';
const LICENSE_OPTION_LTS_IDENTIFIER = '1.2.3.4.5.6.7.8.9';
export const getEnterpriseEditionInfo = (settings) => {
  if (isNotEmptyField(settings.enterprise_license)) {
    let license_customer = 'Trial';
    let license_validated = false;
    let license_expired = true;
    let license_valid_cert = false;
    let license_platform_match = false;
    let license_expiration_date = now();
    let license_start_date = now();
    let license_platform = settings.internal_id;
    let license_expiration_prevention = false;
    let license_lts = false;
    try {
      const clientCrt = forge.pki.certificateFromPem(settings.enterprise_license);
      license_valid_cert = OPENCTI_CA.verify(clientCrt);
      license_lts = clientCrt.extensions.find((ext) => ext.id === LICENSE_OPTION_LTS_IDENTIFIER)?.value === '1';
      license_customer = clientCrt.subject.getField('O').value;
      license_platform = clientCrt.subject.getField('OU').value;
      license_platform_match = license_platform === GLOBAL_LICENSE_OPTION || settings.internal_id === license_platform;
      license_expired = new Date() > clientCrt.validity.notAfter || new Date() < clientCrt.validity.notBefore;
      license_start_date = clientCrt.validity.notBefore;
      license_expiration_date = clientCrt.validity.notAfter;
      license_expiration_prevention = utcDate(clientCrt.validity.notAfter).diff(now(), 'months') < 3;
      license_validated = license_valid_cert && license_platform_match && !license_expired;
    } catch {
      // Nothing to do here
    }
    return {
      license_enterprise: true, // If EE activated
      license_validated, // If EE license is ok (identifier, dates, ...)
      license_valid_cert, // If EE license is Filigran generated
      license_customer,
      license_expired,
      license_expiration_date,
      license_start_date,
      license_expiration_prevention,
      license_platform,
      license_lts,
      license_platform_match
    };
  }
  return {
    license_enterprise: false,
    license_validated: false,
    license_valid_cert: false,
    license_customer: 'invalid',
    license_expired: true,
    license_expiration_date: now(),
    license_start_date: now(),
    license_platform: 'invalid',
    license_lts: false,
    license_expiration_prevention: false,
    license_platform_match: true
  };
};
