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

import { useFormatter } from '../../../../../../../components/i18n';
import { FieldOption } from '../../../../../../../utils/field';
import { PlaybookUpdateAction } from './playbookAction-types';
import type { CustomFieldDefinition } from '../../../../../common/custom_fields/useCustomFieldDefinitions';

const useActionFieldOptions = (customFieldDefinitions: CustomFieldDefinition[] = []) => {
  const { t_i18n } = useFormatter();

  return (action: PlaybookUpdateAction) => {
    let fieldOptions: FieldOption[] = [];
    if (action.op === 'add') {
      fieldOptions = [
        { label: t_i18n('Marking definitions'), value: 'objectMarking' },
        { label: t_i18n('Labels'), value: 'objectLabel' },
        { label: t_i18n('Assignees'), value: 'objectAssignee' },
        { label: t_i18n('Participants'), value: 'objectParticipant' },
        { label: t_i18n('Kill chains'), value: 'killChainPhases' },
        { label: t_i18n('Indicator types'), value: 'indicator_types' },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms' },
      ];
    } else if (action.op === 'replace') {
      fieldOptions = [
        { label: t_i18n('Marking definitions'), value: 'objectMarking' },
        { label: t_i18n('Labels'), value: 'objectLabel' },
        { label: t_i18n('Author'), value: 'createdBy' },
        { label: t_i18n('Confidence'), value: 'confidence' },
        { label: t_i18n('Score'), value: 'x_opencti_score' },
        { label: t_i18n('Assignees'), value: 'objectAssignee' },
        { label: t_i18n('Participants'), value: 'objectParticipant' },
        { label: t_i18n('Severity'), value: 'severity' },
        { label: t_i18n('Priority'), value: 'priority' },
        { label: t_i18n('Kill chains'), value: 'killChainPhases' },
        { label: t_i18n('Indicator types'), value: 'indicator_types' },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms' },
        { label: t_i18n('Detection'), value: 'x_opencti_detection' },
        { label: t_i18n('Status'), value: 'x_opencti_workflow_id' },
      ];
    } else if (action.op === 'remove') {
      fieldOptions = [
        { label: t_i18n('Marking definitions'), value: 'objectMarking' },
        { label: t_i18n('Labels'), value: 'objectLabel' },
        { label: t_i18n('Assignees'), value: 'objectAssignee' },
        { label: t_i18n('Participants'), value: 'objectParticipant' },
        { label: t_i18n('Kill chains'), value: 'killChainPhases' },
        { label: t_i18n('Indicator types'), value: 'indicator_types' },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms' },
      ];
    }
    // As other attributes, a single value custom field is set by replace, a multi_select also accepts add
    if (action.op === 'replace' || action.op === 'remove') {
      fieldOptions = [...fieldOptions, ...customFieldDefinitions.map((d) => ({ label: d.label, value: d.name }))];
    } else if (action.op === 'add') {
      fieldOptions = [...fieldOptions, ...customFieldDefinitions.filter((d) => d.field_type === 'multi_select').map((d) => ({ label: d.label, value: d.name }))];
    }
    return fieldOptions;
  };
};

export default useActionFieldOptions;
