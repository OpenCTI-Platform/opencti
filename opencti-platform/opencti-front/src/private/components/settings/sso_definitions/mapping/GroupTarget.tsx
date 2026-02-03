import React, { useEffect, useState } from 'react';
import { fetchQuery } from 'src/relay/environment';
import { groupsQuery } from '@components/common/form/GroupField';
import { GroupFieldQuery$data } from '@components/common/form/__generated__/GroupFieldQuery.graphql';
import { useFormatter } from 'src/components/i18n';
import { useFormikContext } from 'formik';
import TargetAutocomplete from './TargetAutocomplete';
import { getGroupOrOrganizationMapping } from '@components/settings/sso_definitions/utils/GroupOrOrganizationMapping';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';

type GroupTargetProps = {
  index: number;
  isEditionMode: boolean;
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
};

type FormValues = {
  groups_mapping_source: string[];
  groups_mapping_target: string[];
};

const GroupTarget = ({ index, isEditionMode, updateField }: GroupTargetProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<string[]>([]);

  const { setFieldValue, values } = useFormikContext<FormValues>();

  const fieldName = `groups_mapping_target[${index}]`;
  const value = values.groups_mapping_target?.[index] ?? '';

  useEffect(() => {
    fetchQuery(groupsQuery, { orderBy: 'name', orderMode: 'asc' })
      .toPromise()
      .then((data) => {
        const dataGroups = (data as GroupFieldQuery$data).groups?.edges ?? [];
        const newOptions = dataGroups.map((item) => item?.node.name ?? '').filter((item) => item);
        setOptions(newOptions);
      });
  }, []);

  useEffect(() => {
    if (isEditionMode) {
      const newMapping = getGroupOrOrganizationMapping(values.groups_mapping_source, values.groups_mapping_target);
      if (!newMapping.length) return;
      updateField('groups_mapping', newMapping);
    }
  }, [values.groups_mapping_target, isEditionMode]);

  const handleChange = (_: React.SyntheticEvent, newValue: string) => {
    setFieldValue(fieldName, newValue);
  };

  return (
    <TargetAutocomplete
      label={t_i18n('Groups')}
      itemIcon="Group"
      options={options.filter((item) => item.startsWith(value ?? ''))}
      value={value}
      fieldName={fieldName}
      handleChange={handleChange}
    />
  );
};

export default GroupTarget;
