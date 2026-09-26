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

import useAuth from './useAuth';

// The Enterprise Edition is granted by the XTM license of XTM One, not by an OpenCTI license.
export const isEnterpriseEditionFromXtmOne = (enterpriseEdition?: { license_source?: string | null } | null) => {
  return enterpriseEdition?.license_source === 'XTM_ONE_LICENSE';
};

const useEnterpriseEdition = (): boolean => {
  const { settings } = useAuth();
  return settings.platform_enterprise_edition?.license_validated;
};

export default useEnterpriseEdition;
