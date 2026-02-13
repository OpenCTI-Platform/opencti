import React, { useEffect, useState } from 'react';
import { fetchQuery } from 'src/relay/environment';
import { useFormatter } from 'src/components/i18n';
import { useFormikContext } from 'formik';
import { searchObjectOrganizationFieldQuery as organizationsQuery } from '@components/common/form/ObjectOrganizationField';
import TargetAutocomplete from '@components/settings/sso_definitions/mapping/TargetAutocomplete';
import { ObjectOrganizationFieldQuery$data } from '@components/common/form/__generated__/ObjectOrganizationFieldQuery.graphql';

type OrganizationTargetProps = {
  index: number;
};

const OrganizationTarget = ({ index }: OrganizationTargetProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<string[]>([]);

  const { setFieldValue } = useFormikContext();

  const fieldName = `organizations_mapping_target[${index}]`;

  useEffect(() => {
    fetchQuery(organizationsQuery, { orderBy: 'name', orderMode: 'asc' })
      .toPromise()
      .then((data) => {
        const dataGroups = (data as ObjectOrganizationFieldQuery$data).organizations?.edges ?? [];
        const newOptions = dataGroups.map((item) => item?.node.name ?? '').filter((item) => item);
        setOptions(newOptions);
      });
  }, []);

  const handleChange = (_: React.SyntheticEvent, value: string) => {
    setFieldValue(fieldName, value);
  };

  return (
    <TargetAutocomplete
      fieldName={fieldName}
      handleChange={handleChange}
      itemIcon="Organization"
      label={t_i18n('Organization')}
      options={options}
    />
  );
};

export default OrganizationTarget;
