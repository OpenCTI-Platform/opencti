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

import type { FieldOption } from '../../../../utils/field';
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
  // Properties for "THREAT_LANDSCAPE" PIR
  locations: FieldOption[]
  sectors: FieldOption[]
}

/**
 * Helper function to convert a list of entities to a PIR criteria.
 *
 * @param options List of entities to filter.
 * @param relType Type of the relation linked to the entities.
 * @returns An array of criteria for PIR.
 */
const formOptionsToPirCriteria = (options: FieldOption[], relType: string): PirAddInput['pir_criteria'] => {
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

/**
 * Transforms data of PIR creation form to API input.
 *
 * @param data Form data to convert.
 * @returns Object compatible with API format.
 */
export const pirFormDataToMutationInput = (data: PirCreationFormData): PirAddInput => {
  let criteria: PirAddInput['pir_criteria'] = [];
  if (data.pir_type === 'THREAT_LANDSCAPE') {
    criteria = [
      ...formOptionsToPirCriteria(data.locations, 'targets'),
      ...formOptionsToPirCriteria(data.sectors, 'targets'),
    ];
  }

  return {
    name: data.name,
    pir_type: data.pir_type,
    description: data.description || undefined,
    pir_rescan_days: Number(data.pir_rescan_days),
    pir_criteria: criteria,
    pir_filters: {
      mode: 'and',
      filterGroups: [],
      filters: [{
        key: ['confidence'],
        values: [`${data.confidence ?? 0}`],
        operator: 'gte',
        mode: 'or',
      }],
    },
  };
};
