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
