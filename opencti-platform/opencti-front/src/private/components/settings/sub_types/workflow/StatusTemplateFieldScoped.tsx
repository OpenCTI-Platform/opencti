import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Option } from '@components/common/form/ReferenceField';
import { Field } from 'formik';
import { Label } from 'mdi-material-ui';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import AutocompleteField from '../../../../../components/AutocompleteField';
import { StatusTemplateFieldScopedSearchQuery$data } from './__generated__/StatusTemplateFieldScopedSearchQuery.graphql';

interface StatusTemplateFieldScopedProps {
  name: string;
  setFieldValue: (field: string, value: Option) => void;
  helpertext: string;
  required?: boolean;
  onChange?: (field: string, value: Option) => void;
  style?: Record<string, string | number>;
  scope: string;
}

export const StatusTemplateFieldScopedSearchQuery = graphql`
  query StatusTemplateFieldScopedSearchQuery($search: String, $scope:StatusScope) {
      statusTemplatesByStatusScope(search: $search, scope:$scope) {
        id
        name
        color
    }
  }
`;

const StatusTemplateFieldScoped: FunctionComponent<StatusTemplateFieldScopedProps> = ({
  name,
  style,
  helpertext,
  required = false,
  scope,
}) => {
  const { t_i18n } = useFormatter();
  const [statusTemplates, setStatusTemplates] = useState<Option[]>([]);

  const searchStatusTemplates = (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    fetchQuery(StatusTemplateFieldScopedSearchQuery, {
      search: event && event.target.value ? event.target.value : '',
      scope,
    })
      .toPromise()
      .then((data) => {
        const queryData: StatusTemplateFieldScopedSearchQuery$data = data as unknown as StatusTemplateFieldScopedSearchQuery$data;
        const fieldData: Option[] = queryData?.statusTemplatesByStatusScope?.map((statusData: Option) => {
          return { label: statusData?.name, value: statusData?.id, color: statusData?.color };
        }) || [];
        setStatusTemplates(fieldData);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        style={style}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n('Name'),
          helperText: helpertext,
          onFocus: searchStatusTemplates,
        }}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={statusTemplates}
        onInputChange={searchStatusTemplates}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { color: string; label: string },
        ) => (
          <li {...props}>
            <div style={{ color: option.color }}>
              <Label />
            </div>
            <div>{option.label}</div>
          </li>
        )}
      />
    </div>
  );
};

export default StatusTemplateFieldScoped;
