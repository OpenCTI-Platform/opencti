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

import type { FieldOption } from '../../../utils/field';
import { PirAddInput } from './__generated__/PirCreationMutation.graphql';

export interface PirEditionFormData {
  name: string | null
  description: string | null
}

export interface PirCreationFormData {
  pir_type: 'THREAT_LANDSCAPE' | 'THREAT_ORIGIN' | 'THREAT_CUSTOM'
  name: string
  description: string
  pir_rescan_days: number
  confidence: number | null
  // TODO PIR should have different defs depending of type
  locations: FieldOption[]
  sectors: FieldOption[]
}

const optionsToFilters = (options: FieldOption[], relType: string): PirAddInput['pir_criteria'] => {
  return options.map((option) => ({
    weight: 1,
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: ['entity_type'], values: [relType], operator: 'eq', mode: 'or' },
        { key: ['toId'], values: [option.value], operator: 'eq', mode: 'or' },
      ],
    },
  }));
};

export const pirFormDataToMutationInput = (data: PirCreationFormData): PirAddInput => {
  return {
    name: data.name,
    pir_type: data.pir_type,
    description: data.description ?? undefined,
    pir_rescan_days: Number(data.pir_rescan_days),
    pir_filters: {
      mode: 'and',
      filterGroups: [],
      filters: [{ key: ['confidence'], values: [`${data.confidence}`], operator: 'gte', mode: 'or' }],
    },
    pir_criteria: [
      ...optionsToFilters(data.locations, 'targets'),
      ...optionsToFilters(data.sectors, 'targets'),
    ],
  };
};
