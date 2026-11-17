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

import { useField } from 'formik';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import ObjectOrganizationField from '../../../../common/form/ObjectOrganizationField';
import { useFormatter } from '../../../../../../components/i18n';
import { isDeletedReference } from '../../utils/playbookNodeSummary';

interface OrganizationOption {
  label?: string;
  value: string;
  deleted?: boolean;
}

const PlaybookFlowFieldOrganizations = () => {
  const { t_i18n } = useFormatter();
  const [{ value }] = useField<OrganizationOption[] | undefined>('organizations');
  // The server flags an organization that no longer exists on this platform (deleted, or a
  // playbook imported from another one, #15762): it is named "<label> - deleted" until replaced.
  const hasDeleted = (value ?? []).some(isDeletedReference);
  return (
    <ObjectOrganizationField
      multiple
      alert={false}
      name="organizations"
      label="Target organizations"
      style={fieldSpacingContainerStyle}
      helpertext={hasDeleted ? t_i18n('A selected item no longer exists: remove it and pick another') : undefined}
      getOptionLabel={(option: OrganizationOption) => (isDeletedReference(option)
        ? `${option.label ?? t_i18n('Unknown')} - ${t_i18n('deleted')}`
        : option.label ?? '')}
    />
  );
};

export default PlaybookFlowFieldOrganizations;
