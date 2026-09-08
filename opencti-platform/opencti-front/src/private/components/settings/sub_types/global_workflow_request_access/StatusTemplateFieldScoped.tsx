import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Field } from 'formik';
import { Label } from 'mdi-material-ui';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../../components/ComboboxField';
import { FieldOption } from '../../../../../utils/field';
import { StatusTemplateFieldScopedSearchQuery$data } from './__generated__/StatusTemplateFieldScopedSearchQuery.graphql';

interface StatusTemplateFieldScopedProps {
  name: string;
  setFieldValue: (field: string, value: FieldOption) => void;
  helpertext: string;
  required?: boolean;
  onChange?: (field: string, value: FieldOption) => void;
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
  const [statusTemplates, setStatusTemplates] = useState<FieldOption[]>([]);

  const searchStatusTemplates = (search: string) => {
    fetchQuery(StatusTemplateFieldScopedSearchQuery, {
      search,
      scope,
    })
      .toPromise()
      .then((data) => {
        const queryData: StatusTemplateFieldScopedSearchQuery$data = data as unknown as StatusTemplateFieldScopedSearchQuery$data;
        const fieldData = queryData?.statusTemplatesByStatusScope?.map((statusData) => {
          return { label: statusData?.name, value: statusData?.id, color: statusData?.color } as FieldOption;
        }) || [];
        setStatusTemplates(fieldData);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={ComboboxField}
        name={name}
        style={style}
        label={label}
        helperText={helpertext}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={statusTemplates}
        onInputChange={(search: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type') searchStatusTemplates(search);
        }}
        onFocusInput={() => searchStatusTemplates('')}
        renderOption={(option: { color: string; label: string }) => (
          <>
            <div style={{ color: option.color, paddingTop: 4, display: 'inline-block' }}>
              <Label />
            </div>
            <div style={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
          </>
        )}
      />
    </div>
  );
};

export default StatusTemplateFieldScoped;
