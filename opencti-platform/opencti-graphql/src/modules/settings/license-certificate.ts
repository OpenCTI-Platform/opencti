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

import type { pki } from 'node-forge';

// The Filigran license certificate format, shared by the OpenCTI license and the XTM license checks.

export const GLOBAL_LICENSE_OPTION = 'global';
const LICENSE_TYPE_STANDARD = 'standard';
const LICENSE_TYPE_NFR = 'nfr';
export const LICENSE_TYPE_TRIAL = 'trial';
export const LICENSE_TYPE_LTS = 'lts';
export const LICENSE_TYPE_CI = 'ci';
export const LICENSE_TYPES = [
  LICENSE_TYPE_STANDARD,
  LICENSE_TYPE_NFR,
  LICENSE_TYPE_TRIAL,
  LICENSE_TYPE_LTS,
  LICENSE_TYPE_CI,
];

// https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
// 62944 - Filigran
export const LICENSE_OID_TYPE = '1.3.6.1.4.1.62944.10';
export const LICENSE_OID_PRODUCT = '1.3.6.1.4.1.62944.20';
export const LICENSE_OID_CREATOR = '1.3.6.1.4.1.62944.30';
// Legacy OIDs
export const LICENSE_LEGACY_TYPE = '6.2.9.4.4.10';
export const LICENSE_LEGACY_PRODUCT = '6.2.9.4.4.20';
export const LICENSE_LEGACY_CREATOR = '6.2.9.4.4.30';

export const getExtensionValue = (clientCrt: pki.Certificate, standardOid: string, legacyOid?: string) => {
  const extStandard = clientCrt.extensions.find((ext) => ext.id === standardOid);
  if (extStandard) {
    return extStandard.value;
  }
  return clientCrt.extensions.find((ext) => ext.id === legacyOid)?.value;
};

// A ci license ends 45 minutes after the platform creation, and never later than a year after its start.
const CI_LICENSE_PLATFORM_LIFETIME = 45 * 60 * 1000;
const CI_LICENSE_MAX_LIFETIME = 365 * 24 * 60 * 60 * 1000;
export const computeCiLicenseExpirationDate = (platformCreatedAt: Date, licenseStartDate: Date) => {
  const ciPlatformEndDate = new Date(platformCreatedAt.getTime() + CI_LICENSE_PLATFORM_LIFETIME);
  const certEndDate = new Date(licenseStartDate.getTime() + CI_LICENSE_MAX_LIFETIME);
  return ciPlatformEndDate < certEndDate ? ciPlatformEndDate : certEndDate;
};
