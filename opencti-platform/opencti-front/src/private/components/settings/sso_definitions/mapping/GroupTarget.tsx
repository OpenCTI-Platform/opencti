import React, { useEffect, useState } from 'react';
import { fetchQuery } from 'src/relay/environment';
import { groupsQuery } from '@components/common/form/GroupField';
import { GroupFieldQuery$data } from '@components/common/form/__generated__/GroupFieldQuery.graphql';
import { useFormatter } from 'src/components/i18n';
import { useFormikContext } from 'formik';
import TargetAutocomplete from './TargetAutocomplete';

type GroupTargetProps = {
  index: number;
};

const GroupTarget = ({ index }: GroupTargetProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<string[]>([]);

  const { setFieldValue } = useFormikContext();

  const fieldName = `groups_mapping_target[${index}]`;

  useEffect(() => {
    fetchQuery(groupsQuery, { orderBy: 'name', orderMode: 'asc' })
      .toPromise()
      .then((data) => {
        const dataGroups = (data as GroupFieldQuery$data).groups?.edges ?? [];
        const newOptions = dataGroups.map((item) => item?.node.name ?? '').filter((item) => item);
        setOptions(newOptions);
      });
  }, []);

  const handleChange = (_: React.SyntheticEvent, value: string) => {
    setFieldValue(fieldName, value);
  };

  return (
    <TargetAutocomplete
      label={t_i18n('Groups')}
      itemIcon="Group"
      options={options}
      handleChange={handleChange}
      fieldName={fieldName}
    />
  );
};

export default GroupTarget;
