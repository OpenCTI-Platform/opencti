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

import { Field, useFormikContext } from 'formik';
import SwitchField from '../../../../../../../components/fields/SwitchField';
import { FieldOption, fieldSpacingContainerStyle, KillChainPhaseFieldOption } from '../../../../../../../utils/field';
import { isEmptyField } from '../../../../../../../utils/utils';
import CreatedByField from '../../../../../common/form/CreatedByField';
import KillChainPhasesField from '../../../../../common/form/KillChainPhasesField';
import ObjectAssigneeField from '../../../../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../../../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../../../../common/form/ObjectMarkingField';
import ObjectParticipantField from '../../../../../common/form/ObjectParticipantField';
import OpenVocabField from '../../../../../common/form/OpenVocabField';
import StatusField from '../../../../../common/form/StatusField';
import { PlaybookUpdateAction, PlaybookUpdateActionsForm } from './playbookAction-types';
import TextField from '../../../../../../../components/TextField';
import useAttributes from '../../../../../../../utils/hooks/useAttributes';
import { useFormatter } from '../../../../../../../components/i18n';

interface PlaybookActionValueFieldProps {
  action: PlaybookUpdateAction
  index: number
}

const PlaybookActionValueField = ({
  action,
  index,
}: PlaybookActionValueFieldProps) => {
  const { t_i18n } = useFormatter();
  const { numberAttributes } = useAttributes();
  const { setFieldValue } = useFormikContext<PlaybookUpdateActionsForm>();

  const disabled = isEmptyField(action.attribute);
  // Represents format of the value for backend manipulation.
  const valueName = `actions.${index}.value`;
  // Represents format of the value for the frontend form.
  // /!\ It's relicate from old code and cannot be changed without breaking old playbooks.
  const formValueName = `actions-${index}-value`;

  switch (action.attribute) {
    case 'objectMarking':
      return (
        <ObjectMarkingField
          name={formValueName}
          disabled={disabled}
          onChange={(_, markings) => {
            setFieldValue(
              valueName,
              markings.map((marking) => ({
                label: marking.label,
                value: marking.value,
                patch_value: marking.value,
              })),
            );
          }}
        />
      );
    case 'objectLabel':
      return (
        <ObjectLabelField
          name={formValueName}
          disabled={disabled}
          onChange={(_, labels) => {
            setFieldValue(
              valueName,
              labels.map((label) => ({
                label: label.label,
                value: label.value,
                patch_value: label.label,
              })),
            );
          }}
        />
      );
    case 'createdBy':
      return (
        <CreatedByField
          name={formValueName}
          disabled={disabled}
          onChange={(_: string, author: FieldOption) => {
            setFieldValue(
              valueName,
              [{
                label: author.label,
                value: author.value,
                patch_value: author.value,
              }],
            );
          }}
        />
      );
    case 'objectAssignee':
      return (
        <ObjectAssigneeField
          name={formValueName}
          disabled={disabled}
          onChange={(_, assignees) => {
            setFieldValue(
              valueName,
              assignees.map((assignee) => ({
                label: assignee.label,
                value: assignee.value,
                patch_value: assignee.value,
              })),
            );
          }}
        />
      );
    case 'objectParticipant':
      return (
        <ObjectParticipantField
          name={formValueName}
          disabled={disabled}
          onChange={(_, participants) => {
            setFieldValue(
              valueName,
              participants.map((participant) => ({
                label: participant.label,
                value: participant.value,
                patch_value: participant.value,
              })),
            );
          }}
        />
      );
    case 'x_opencti_workflow_id':
      return (
        <StatusField
          name={formValueName}
          disabled={disabled}
          onChange={(_: string, workflow: FieldOption) => {
            setFieldValue(
              valueName,
              [{
                label: workflow.label,
                value: workflow.value,
                patch_value: workflow.value,
              }],
            );
          }}
        />
      );
    case 'x_opencti_detection':
      return (
        <Field
          component={SwitchField}
          type="checkbox"
          name={formValueName}
          label={t_i18n('Value')}
          onChange={(_: string, detection: string) => {
            setFieldValue(
              valueName,
              [{
                label: detection,
                value: detection,
                patch_value: detection,
              }],
            );
          }}
        />
      );
    case 'severity':
      return (
        <OpenVocabField
          name={formValueName}
          type={'case_severity_ov'}
          containerStyle={fieldSpacingContainerStyle}
          onChange={(_, severity) => {
            setFieldValue(
              valueName,
              [{
                label: severity,
                value: severity,
                patch_value: severity,
              }],
            );
          }}
        />
      );
    case 'indicator_types':
      return (
        <OpenVocabField
          name={formValueName}
          type="indicator_type_ov"
          containerStyle={fieldSpacingContainerStyle}
          multiple
          onChange={(_, indicatorTypes) => {
            setFieldValue(
              valueName,
              (indicatorTypes as string[]).map((type) => ({
                label: type,
                value: type,
                patch_value: type,
              })),
            );
          }}
        />
      );
    case 'x_mitre_platforms':
      return (
        <OpenVocabField
          name={formValueName}
          type="platforms_ov"
          containerStyle={fieldSpacingContainerStyle}
          multiple
          onChange={(_, mitrePlatforms) => {
            setFieldValue(
              valueName,
              (mitrePlatforms as string[]).map((platform) => ({
                label: platform,
                value: platform,
                patch_value: platform,
              })),
            );
          }}
        />
      );
    case 'priority':
      return (
        <OpenVocabField
          name={formValueName}
          type="case_priority_ov"
          containerStyle={fieldSpacingContainerStyle}
          onChange={(_, priority) => {
            setFieldValue(
              valueName,
              [{
                label: priority,
                value: priority,
                patch_value: priority,
              }],
            );
          }}
        />
      );
    case 'killChainPhases':
      return (
        <KillChainPhasesField
          name={formValueName}
          onChange={(_: string, killChainPhases: KillChainPhaseFieldOption[]) => {
            setFieldValue(
              valueName,
              killChainPhases.map((kcp) => ({
                label: kcp.label,
                value: kcp.value,
                patch_value: {
                  kill_chain_name: kcp.kill_chain_name,
                  phase_name: kcp.phase_name,
                },
              })),
            );
          }}
        />
      );
    default:
      return (
        <Field
          component={TextField}
          disabled={disabled}
          type={numberAttributes.includes(action.attribute ?? '') ? 'number' : 'text'}
          variant="standard"
          name={formValueName}
          label={t_i18n('Value')}
          fullWidth
          onChange={(_: string, val: string) => {
            setFieldValue(
              valueName,
              [{
                label: val,
                value: val,
                patch_value: val,
              }],
            );
          }}
        />
      );
  }
};

export default PlaybookActionValueField;
