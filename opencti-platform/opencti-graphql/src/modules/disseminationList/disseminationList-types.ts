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

import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_DISSEMINATION_LIST = 'DisseminationList';

export interface BasicStoreEntityDisseminationList extends BasicStoreEntity {
  name: string;
  emails: string[];
  description: string;
  dissemination_list_values_count: number;
}

export interface StoreEntityDisseminationList extends StoreEntity {
  name: string;
  emails: string[];
  description: string;
  dissemination_list_values_count: number;
}

export interface StixDisseminationList extends StixObject {
  name: string;
  emails: string[];
  description: string;
  dissemination_list_values_count: number;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  };
}
