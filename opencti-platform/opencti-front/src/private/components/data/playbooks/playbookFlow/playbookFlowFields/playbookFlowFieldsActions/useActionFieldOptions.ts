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

const useActionFieldOptions = () => {
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
    return fieldOptions;
  };
};

export default useActionFieldOptions;
