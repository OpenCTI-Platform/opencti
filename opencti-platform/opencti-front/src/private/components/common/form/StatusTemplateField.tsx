import React, { FunctionComponent, useState } from 'react';
import { Field, useFormikContext } from 'formik';
import { Label } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
import StatusTemplateCreation from '../../settings/status_templates/StatusTemplateCreation';
import { useFormatter } from '../../../../components/i18n';
import { StatusTemplateFieldSearchQuery$data } from './__generated__/StatusTemplateFieldSearchQuery.graphql';
import { StatusTemplateCreationContextualMutation$data } from '../../settings/status_templates/__generated__/StatusTemplateCreationContextualMutation.graphql';
import { FieldOption } from '../../../../utils/field';

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
}));

interface StatusTemplateFieldProps {
  name: string;
  setFieldValue: (field: string, value: FieldOption) => void;
  helpertext: string;
  required?: boolean;
  onChange?: (field: string, value: FieldOption) => void;
  style?: Record<string, string | number>;
  label?: string;
}

export const StatusTemplateFieldQuery = graphql`
  query StatusTemplateFieldSearchQuery($search: String) {
    statusTemplates(search: $search) {
      edges {
        node {
          id
          name
          color
        }
      }
    }
  }
`;

const StatusTemplateField: FunctionComponent<StatusTemplateFieldProps> = ({
  name,
  style,
  setFieldValue,
  helpertext,
  required = false,
  label,
}) => {
  const { values } = useFormikContext<Record<string, { value: string; label: string; color: string } | { id: string; name: string; color: string }>>();
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

  const handleSearch = (value = '') => {
    setStatusTemplateInput(value);
    fetchQuery(StatusTemplateFieldQuery, value ? { search: value } : {})
      .toPromise()
      .then((data) => {
        const NewStatusTemplates = (
          (data as StatusTemplateFieldSearchQuery$data)?.statusTemplates
            ?.edges ?? []
        ).map((n) => ({
          label: n?.node.name,
          value: n?.node.id,
          color: n?.node.color,
        }));
        const templateValues = [...statusTemplates, ...NewStatusTemplates];
        // Keep only the unique list of options
        const uniqTemplates = templateValues.filter((item, index) => {
          return (
            templateValues.findIndex((e) => e.value === item.value) === index
          );
        });
        setStatusTemplates(uniqTemplates);
      });
  };

  const fieldValue = values[name];

  const normalizedValue = (fieldValue && 'id' in fieldValue)
    ? { value: fieldValue.id, label: fieldValue.name, color: fieldValue.color }
    : (fieldValue ?? null);

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={ComboboxField}
        // MUI hid its clear indicator here with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        clearable={false}
        name={name}
        style={style}
        value={normalizedValue}
        onChange={(name: string, value: FieldOption) => {
          if (setFieldValue) {
            setFieldValue(name, value);
          }
        }}
        label={label && t_i18n('Name')}
        helperText={helpertext}
        // Prevent filtering on previous status
        onFocusInput={() => handleSearch('')}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={statusTemplates}
        onInputChange={(value: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type') handleSearch(value);
        }}
        onCreateOption={handleOpenStatusTemplateCreation}
        renderOption={(option: { color: string; label: string }) => (
          <>
            <div className={classes.icon} style={{ color: option.color }}>
              <Label />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
      />
      <StatusTemplateCreation
        contextual={true}
        inputValueContextual={statusTemplateInput}
        open={statusTemplateCreation}
        handleClose={handleCloseStatusTemplateCreation}
        creationCallback={({
          statusTemplateAdd: data,
        }: StatusTemplateCreationContextualMutation$data) => {
          setFieldValue(name, {
            value: data.id,
            label: data.name,
          });
        }}
      />
    </div>
  );
};

export default StatusTemplateField;
