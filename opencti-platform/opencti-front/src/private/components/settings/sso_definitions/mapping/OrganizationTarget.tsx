import React, { useEffect, useState } from 'react';
import { fetchQuery } from 'src/relay/environment';
import { useFormatter } from 'src/components/i18n';
import { useFormikContext } from 'formik';
import { searchObjectOrganizationFieldQuery as organizationsQuery } from '@components/common/form/ObjectOrganizationField';
import TargetAutocomplete from '@components/settings/sso_definitions/mapping/TargetAutocomplete';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import { getGroupOrOrganizationMapping } from '@components/settings/sso_definitions/utils/GroupOrOrganizationMapping';
import { ObjectOrganizationFieldQuery$data } from '@components/common/form/__generated__/ObjectOrganizationFieldQuery.graphql';

type OrganizationTargetProps = {
  index: number;
  isEditionMode: boolean;
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
};

type FormValues = {
  organizations_mapping_source: string[];
  organizations_mapping_target: string[];
};

const OrganizationTarget = ({ index, isEditionMode, updateField }: OrganizationTargetProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<string[]>([]);

  const { values, setFieldValue } = useFormikContext<FormValues>();

  const fieldName = `organizations_mapping_target[${index}]`;
  const value = values.organizations_mapping_target?.[index] ?? '';

  useEffect(() => {
    fetchQuery(organizationsQuery, { orderBy: 'name', orderMode: 'asc' })
      .toPromise()
      .then((data) => {
        const dataGroups = (data as ObjectOrganizationFieldQuery$data).organizations?.edges ?? [];
        const newOptions = dataGroups.map((item) => item?.node.name ?? '').filter((item) => item);
        setOptions(newOptions);
      });
  }, []);

  useEffect(() => {
    if (isEditionMode) {
      const newMapping = getGroupOrOrganizationMapping(values.organizations_mapping_source, values.organizations_mapping_target);
      if (!newMapping.length) return;
      updateField('organizations_mapping', newMapping);
    }
  }, [values.organizations_mapping_target]);

  const handleChange = (_: React.SyntheticEvent, value: string) => {
    setFieldValue(fieldName, value);
  };

  return (
    <TargetAutocomplete
      fieldName={fieldName}
      handleChange={handleChange}
      itemIcon="Organization"
      label={t_i18n('Organization')}
      options={options.filter((item) => item.startsWith(value ?? ''))}
      value={value}
    />
  );
};

export default OrganizationTarget;
