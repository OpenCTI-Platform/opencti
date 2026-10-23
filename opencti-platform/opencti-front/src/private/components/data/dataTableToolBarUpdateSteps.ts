import { isCustomFieldAttribute } from '../../../utils/customFields';

// One step of the "Update entities" drawer: an action type on a field with its values
export interface UpdateStep {
  type?: string;
  field?: string;
  fieldType?: 'ATTRIBUTE' | 'RELATION';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  values?: any[];
  options?: Record<string, boolean>;
  inputValue?: string;
}

interface CustomFieldDefinition {
  name: string;
  field_type: string;
}

const relationFields = ['object-marking', 'object-label', 'created-by', 'external-reference', 'object-assignee', 'object-participant'];
const temporalFields = ['start_time', 'stop_time'];

// Vocabulary fields are sent to the task with the attribute they fill and their labels as values
const categoryAttributeMapping: Record<string, string> = {
  case_severity_ov: 'severity',
  case_priority_ov: 'priority',
  incident_response_types_ov: 'response_types',
  request_for_information_types_ov: 'information_types',
  request_for_takedown_types_ov: 'takedown_types',
  indicator_type_ov: 'indicator_types',
  platforms_ov: 'x_mitre_platforms',
};

const updateStep = (steps: UpdateStep[], i: number, update: (step: UpdateStep) => UpdateStep): UpdateStep[] => {
  const nextSteps = [...steps];
  nextSteps[i] = update(steps[i] ?? {});
  return nextSteps;
};

const toArray = <T>(value: T | T[]): T[] => (Array.isArray(value) ? value : [value]);

const defaultValuesOfField = (step: UpdateStep, field: string, customFieldDefinitions: readonly CustomFieldDefinition[]) => {
  const customFieldDefinition = customFieldDefinitions.find((d) => d.name === field);
  if (customFieldDefinition?.field_type === 'boolean' && step.type !== 'REMOVE') return ['false'];
  if (field === 'x_opencti_detection') return ['false'];
  if (field === 'password_valid_until') return [new Date().toISOString()];
  if (temporalFields.includes(field) && step.type === 'REMOVE') return [''];
  return [];
};

export const addStep = (steps: UpdateStep[]): UpdateStep[] => [...steps, {}];

export const removeStep = (steps: UpdateStep[], i: number): UpdateStep[] => steps.filter((_, index) => index !== i);

// Changing the field also resets the values and sets the field type
export const changeStepKey = (
  steps: UpdateStep[],
  i: number,
  key: 'type' | 'field',
  value: string,
  customFieldDefinitions: readonly CustomFieldDefinition[] = [],
): UpdateStep[] => updateStep(steps, i, (step) => {
  const nextStep = { ...step, [key]: value };
  if (key !== 'field') return nextStep;
  return {
    ...nextStep,
    values: defaultValuesOfField(nextStep, value, customFieldDefinitions),
    fieldType: relationFields.includes(value) ? 'RELATION' : 'ATTRIBUTE',
  };
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const setStepValues = (steps: UpdateStep[], i: number, value: any): UpdateStep[] => {
  return updateStep(steps, i, (step) => ({ ...step, values: toArray(value) }));
};

export const setStepOption = (steps: UpdateStep[], i: number, key: string, checked: unknown): UpdateStep[] => {
  return updateStep(steps, i, (step) => ({ ...step, options: { ...step.options, [key]: checked === true } }));
};

export const setStepInputValue = (steps: UpdateStep[], i: number, value: unknown): UpdateStep[] => {
  const inputValue = typeof value === 'string' && value.length > 0 ? value : '';
  return updateStep(steps, i, (step) => ({ ...step, inputValue }));
};

export const setStepSwitchValue = (steps: UpdateStep[], i: number, key: string, value: boolean): UpdateStep[] => {
  return updateStep(steps, i, (step) => ({ ...step, [key]: key === 'values' ? [String(value)] : value }));
};

// Removing a start or stop time clears it: no date can be picked
export const isTemporalFieldRemoval = (step: UpdateStep | undefined): boolean => {
  return step?.type === 'REMOVE' && temporalFields.includes(step.field ?? '');
};

// Array.from turns the empty slots into undefined steps, which are not valid
export const areStepsValid = (steps: UpdateStep[]): boolean => Array.from(steps).every((step) => {
  // Removing a custom field without value clears it
  const isCustomFieldClear = step?.type === 'REMOVE' && isCustomFieldAttribute(step.field) && Array.isArray(step.values);
  return !!step && !!step.type && !!step.field && !!step.values && (step.values.length > 0 || isCustomFieldClear);
});

export const buildUpdateActions = (steps: UpdateStep[]) => steps.map((step) => {
  const mappedField = step.field ? categoryAttributeMapping[step.field] : undefined;
  return {
    type: step.type,
    context: {
      field: mappedField ?? step.field,
      type: step.fieldType,
      values: mappedField ? (step.values ?? []).map((value) => value.label) : step.values,
      options: step.options,
    },
  };
});
