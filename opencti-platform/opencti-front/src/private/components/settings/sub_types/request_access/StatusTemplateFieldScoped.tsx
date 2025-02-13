import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { Option } from '@components/common/form/ReferenceField';
import { Field } from 'formik';
import { Label } from 'mdi-material-ui';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import AutocompleteField from '../../../../../components/AutocompleteField';
// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

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
  query StatusTemplateFieldScopedSearchQuery($search: String) {
      statusTemplatesByStatusScope(search: $search) {
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
  setFieldValue,
  helpertext,
  required = false,
  scope,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [statusTemplateCreation, setStatusTemplateCreation] = useState<boolean>(false);
  const [statusTemplateInput, setStatusTemplateInput] = useState<string>('');
  const [statusTemplates, setStatusTemplates] = useState<
  {
    label: string | undefined;
    value: string | undefined;
    color: string | undefined;
  }[]
  >([]);

  const handleOpenStatusTemplateCreation = () => setStatusTemplateCreation(true);

  const handleCloseStatusTemplateCreation = () => setStatusTemplateCreation(false);

  const searchStatusTemplates = (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    setStatusTemplateInput(
      event && event.target.value ? event.target.value : '',
    );
    fetchQuery(StatusTemplateFieldScopedSearchQuery, {
      search: event && event.target.value ? event.target.value : '',
      scope,
    })
      .toPromise()
      .then((data: any) => {
        console.log('Data:', data);
        setStatusTemplates({ label: 'label', value: 'value', color: '#fff' });
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
        openCreate={handleOpenStatusTemplateCreation}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { color: string; label: string },
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <Label />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    </div>
  );
};

export default StatusTemplateFieldScoped;
