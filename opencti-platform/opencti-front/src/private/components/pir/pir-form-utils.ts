import type { FieldOption } from '../../../utils/field';
import { PirAddInput } from './__generated__/PirCreationMutation.graphql';

export interface PirCreationFormData {
  type: string | null
  name: string | null
  description: string | null
  markings: FieldOption[]
  confidence: number | null
  // TODO PIR should have different defs depending of type
  locations: FieldOption[]
  sectors: FieldOption[]
}

const optionsToFilters = (options: FieldOption[]): PirAddInput['pir_criteria'] => {
  return options.map((option) => ({
    weight: 1,
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [{ key: ['toId'], values: [option.value], operator: 'eq', mode: 'or' }],
    },
  }));
};

export const pirFormDataToMutationInput = (data: PirCreationFormData): PirAddInput => {
  return {
    name: data.name ?? '',
    description: data.description,
    objectMarking: data.markings.map((m) => m.value),
    pir_filters: {
      mode: 'and',
      filterGroups: [],
      filters: [{ key: ['confidence'], values: [`${data.confidence}`], operator: 'gt', mode: 'or' }],
    },
    pir_criteria: [
      ...optionsToFilters(data.locations),
      ...optionsToFilters(data.sectors),
    ],
  };
};
