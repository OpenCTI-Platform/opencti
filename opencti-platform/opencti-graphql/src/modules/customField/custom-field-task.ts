import * as R from 'ramda';
import type { EditInput } from '../../generated/graphql';
import { EditOperation } from '../../generated/graphql';
import { customFieldValues } from '../../schema/attribute-definition';
import { getCustomFieldValueField } from './custom-field-cache';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldType } from './custom-field-types';

const convertTaskValue = (fieldType: CustomFieldType, value: string) => {
  if (fieldType === 'integer' || fieldType === 'decimal') return Number(value);
  if (fieldType === 'boolean') return value.toLowerCase() === 'true';
  return value;
};

// Edit inputs of a background task action on a custom field (values are sent as strings), applied by the worker
// in a single edit on the current values: a single value field is set by add or replace and cleared by remove,
// a multi_select gets options added, replaced (removed then added) or removed (all of them without value).
export const buildCustomFieldTaskInputs = (
  definition: BasicStoreEntityCustomFieldDefinition,
  actionType: 'ADD' | 'REPLACE' | 'REMOVE',
  values: string[],
): EditInput[] => {
  const key = customFieldValues.name;
  const identity = { field_name: definition.name };
  const isMultiSelect = definition.field_type === 'multi_select';
  const clearInput = { key, operation: EditOperation.Remove, value: [identity] };
  if (actionType === 'REMOVE') {
    return isMultiSelect && values.length > 0
      ? [{ key, operation: EditOperation.Remove, value: [{ ...identity, select_values: values }] }]
      : [clearInput];
  }
  if (values.length === 0) {
    return actionType === 'REPLACE' ? [clearInput] : [];
  }
  if (isMultiSelect) {
    const addInput = { key, operation: EditOperation.Add, value: [{ ...identity, select_values: R.uniq(values) }] };
    return actionType === 'REPLACE' ? [clearInput, addInput] : [addInput];
  }
  const value = convertTaskValue(definition.field_type, values[0]);
  return [{ key, operation: EditOperation.Add, value: [{ ...identity, [getCustomFieldValueField(definition.field_type)]: value }] }];
};
