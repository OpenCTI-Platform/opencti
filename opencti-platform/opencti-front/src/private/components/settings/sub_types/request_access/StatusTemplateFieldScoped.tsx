import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Option } from '@components/common/form/ReferenceField';
import { Field } from 'formik';
import { Label } from 'mdi-material-ui';
import { StatusTemplateFieldScopedSearchQuery$data } from '@components/settings/sub_types/request_access/__generated__/StatusTemplateFieldScopedSearchQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import AutocompleteField from '../../../../../components/AutocompleteField';

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

export interface StatusTemplateFieldData {
  label: string | undefined;
  value: string | undefined;
  color: string | undefined;
}

const StatusTemplateFieldScoped: FunctionComponent<StatusTemplateFieldScopedProps> = ({
  name,
  style,
  helpertext,
  required = false,
  scope,
}) => {
  const { t_i18n } = useFormatter();

  // const [statusTemplateInput, setStatusTemplateInput] = useState<string>('');
  const [statusTemplates, setStatusTemplates] = useState<StatusTemplateFieldData[]>([]);

  const searchStatusTemplates = (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    /* setStatusTemplateInput(
      event && event.target.value ? event.target.value : '',
    ); */
    fetchQuery(StatusTemplateFieldScopedSearchQuery, {
      search: event && event.target.value ? event.target.value : '',
      scope,
    })
      .toPromise()
      .then((data: any) => {
        // console.log('Data:', data);
        const queryData: StatusTemplateFieldScopedSearchQuery$data = data;
        const fieldData: StatusTemplateFieldData[] = queryData?.statusTemplatesByStatusScope?.map((statusData) => {
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
