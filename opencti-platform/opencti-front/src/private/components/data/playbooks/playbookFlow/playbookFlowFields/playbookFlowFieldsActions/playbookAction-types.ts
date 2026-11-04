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

import { customFieldValueToTaskValues, type CustomFieldValue, isCustomFieldAttribute } from '../../../../../../../utils/customFields';
import type { CustomFieldDefinition } from '../../../../../common/custom_fields/useCustomFieldDefinitions';

export interface PlaybookUpdateAction {
  op?: string;
  attribute?: string;
  value?: {
    label?: string;
    value?: string;
    patch_value?: string | {
      kill_chain_name: string;
      phase_name: string;
    };
  }[];
}

export interface PlaybookUpdateActionsForm {
  actions?: PlaybookUpdateAction[];
  actionsFormValues?: PlaybookUpdateAction['value'][];
}

export const attributesMultiple = [
  'objectMarking',
  'objectLabel',
  'objectAssignee',
  'objectParticipant',
  'killChainPhases',
  'indicator_types',
  'x_mitre_platforms',
];

// Custom fields are edited through their technical name (x_opencti_cf_*), their value is sent as strings:
// one entry for a single value, one per option for a multi_select.
export { isCustomFieldAttribute };

export const isAttributeMultiple = (attribute: string | undefined, customFieldDefinitions: CustomFieldDefinition[]) => {
  if (isCustomFieldAttribute(attribute)) {
    return customFieldDefinitions.some((d) => d.name === attribute && d.field_type === 'multi_select');
  }
  return attributesMultiple.includes(attribute ?? '');
};

export const toCustomFieldActionValue = (value: CustomFieldValue): NonNullable<PlaybookUpdateAction['value']> => {
  return customFieldValueToTaskValues(value).map((v) => ({ label: v, value: v, patch_value: v }));
};

// Removing a custom field value clears it (or the given multi_select options): no value is required
export const isPlaybookUpdateActionValid = (action: PlaybookUpdateAction) => {
  if (action.attribute === 'x_opencti_detection') return true;
  if (isCustomFieldAttribute(action.attribute) && action.op === 'remove') return Array.isArray(action.value);
  return !!(action.op && action.attribute && action.value && action.value.length > 0);
};
