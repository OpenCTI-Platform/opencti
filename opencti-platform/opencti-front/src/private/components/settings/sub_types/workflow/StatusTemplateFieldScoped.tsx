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
  label: string;
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
  label,
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
        const fieldData = queryData?.statusTemplatesByStatusScope?.map((statusData) => {
          return { label: statusData?.name, value: statusData?.id, color: statusData?.color } as Option;
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
          label,
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
            <div style={{ color: option.color, paddingTop: 4, display: 'inline-block' }}>
              <Label />
            </div>
            <div style ={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
          </li>
        )}
      />
    </div>
  );
};

export default StatusTemplateFieldScoped;
