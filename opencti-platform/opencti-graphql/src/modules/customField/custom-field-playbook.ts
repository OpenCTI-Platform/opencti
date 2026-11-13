import * as R from 'ramda';
import type * as jsonpatch from 'fast-json-patch';
import type { StixObject } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { EditOperation } from '../../generated/graphql';
import { customFieldValues } from '../../schema/attribute-definition';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldType, CustomFieldValue } from './custom-field-types';
import { extractCustomFieldValueFromAddInputValue } from './custom-field-validator';

export interface CustomFieldPlaybookAction {
  op: 'add' | 'replace' | 'remove';
  attribute: string;
  value: { patch_value: string }[];
}

interface CustomFieldUpsertOperation {
  key: string;
  value: any[];
  operation: 'add' | 'replace' | 'remove';
}

const convertPatchValue = (fieldType: CustomFieldType, value: string) => {
  if (fieldType === 'integer' || fieldType === 'decimal') return Number(value);
  if (fieldType === 'boolean') return value.toLowerCase() === 'true';
  return value;
};

const isEmptyCustomFieldValue = (value: unknown) => value === undefined || value === null || value === ''
  || (Array.isArray(value) && value.length === 0);

// Value of the custom field once the action is applied on its current value.
// A multi_select works as a multiple attribute (add / replace / remove options, remove without value clears it),
// any other type as a single one (add and replace set the value, remove clears it).
export const computeCustomFieldActionValue = (
  definition: BasicStoreEntityCustomFieldDefinition,
  action: CustomFieldPlaybookAction,
  currentValue: unknown,
) => {
  const values = action.value.map((v) => convertPatchValue(definition.field_type, v.patch_value));
  if (definition.field_type === 'multi_select') {
    const currentValues = Array.isArray(currentValue) ? currentValue : [];
    if (action.op === EditOperation.Add) return R.uniq([...currentValues, ...values]);
    if (action.op === EditOperation.Replace) return R.uniq(values);
    return values.length > 0 ? currentValues.filter((v) => !values.includes(v)) : [];
  }
  return action.op === EditOperation.Remove ? undefined : values[0];
};

// Upsert operation of an action, applied on the stored value (not on the bundle snapshot, which may be stale):
// options are added or removed incrementally, as the playbook does for the labels; replace sets the field.
const buildCustomFieldActionUpsertOperation = (
  definition: BasicStoreEntityCustomFieldDefinition,
  action: CustomFieldPlaybookAction,
): CustomFieldUpsertOperation | undefined => {
  const values = action.value.map((v) => convertPatchValue(definition.field_type, v.patch_value));
  const identity = { field_id: definition.id, field_name: definition.name };
  const clear = { key: customFieldValues.name, value: [identity], operation: EditOperation.Remove };
  if (definition.field_type === 'multi_select') {
    if (action.op === EditOperation.Add) {
      return values.length > 0 ? { key: customFieldValues.name, value: [{ ...identity, select_values: R.uniq(values) }], operation: EditOperation.Add } : undefined;
    }
    if (action.op === EditOperation.Remove) {
      return values.length > 0 ? { key: customFieldValues.name, value: [{ ...identity, select_values: values }], operation: EditOperation.Remove } : clear;
    }
  } else if (action.op === EditOperation.Remove) {
    return clear;
  }
  if (values.length === 0) {
    return clear;
  }
  const storedValue = extractCustomFieldValueFromAddInputValue(definition.field_type === 'multi_select' ? R.uniq(values) : [values[0]], definition);
  // A value not matching the field type is ignored, as on ingestion
  return storedValue ? { key: customFieldValues.name, value: [storedValue], operation: EditOperation.Replace } : undefined;
};

// The bundle carries a custom field as a property of the OpenCTI extension (or at the top level when ingested so).
// Changing it there is enough for a new element; an existing one also needs the upsert operations of the actions,
// as the upsert only adds values (a removed key or multi_select option would otherwise be kept).
export const buildCustomFieldPlaybookOperations = (
  element: StixObject,
  elementPath: string,
  actions: CustomFieldPlaybookAction[],
  definitions: BasicStoreEntityCustomFieldDefinition[],
) => {
  const extension = element.extensions[STIX_EXT_OCTI] as Record<string, any>;
  const upsertOperations: CustomFieldUpsertOperation[] = [];
  // Successive actions on the same field apply on the value computed by the previous ones
  const finalValues = new Map<BasicStoreEntityCustomFieldDefinition, { value: unknown; storedValue?: CustomFieldValue }>();
  for (let i = 0; i < actions.length; i += 1) {
    const action = actions[i];
    const definition = definitions.find((d) => d.name === action.attribute);
    if (definition) {
      const upsertOperation = buildCustomFieldActionUpsertOperation(definition, action);
      if (upsertOperation) upsertOperations.push(upsertOperation);
      const currentValue = finalValues.has(definition)
        ? finalValues.get(definition)?.value
        : ((element as any)[definition.name] ?? extension[definition.name]);
      const value = computeCustomFieldActionValue(definition, action, currentValue);
      if (isEmptyCustomFieldValue(value)) {
        finalValues.set(definition, { value: undefined });
      } else {
        const storedValue = extractCustomFieldValueFromAddInputValue(Array.isArray(value) ? value : [value], definition);
        // A value not matching the field type is ignored, as on ingestion
        if (storedValue) finalValues.set(definition, { value, storedValue });
      }
    }
  }
  const patchOperations: jsonpatch.Operation[] = [];
  finalValues.forEach(({ value, storedValue }, definition) => {
    const isTopLevel = Object.hasOwn(element, definition.name);
    const extensionPath = `${elementPath}/extensions/${STIX_EXT_OCTI}/${definition.name}`;
    const topLevelPath = `${elementPath}/${definition.name}`;
    if (!storedValue) {
      if (isTopLevel) patchOperations.push({ op: 'remove', path: topLevelPath });
      if (Object.hasOwn(extension, definition.name)) patchOperations.push({ op: 'remove', path: extensionPath });
    } else {
      patchOperations.push({ op: 'add', path: isTopLevel ? topLevelPath : extensionPath, value });
    }
  });
  return { patchOperations, upsertOperations };
};
