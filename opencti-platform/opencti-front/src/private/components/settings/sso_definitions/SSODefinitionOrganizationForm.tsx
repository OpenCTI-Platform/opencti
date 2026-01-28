import { Field, FieldArray } from 'formik';
import TextField from 'src/components/TextField';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Add, Delete } from '@mui/icons-material';
import React from 'react';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import { useFormatter } from 'src/components/i18n';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import SwitchField from 'src/components/fields/SwitchField';

type SSODefinitionOrganizationFormProps = {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
  selectedStrategy: string | null;
};

const SSODefinitionOrganizationForm = ({ updateField, selectedStrategy }: SSODefinitionOrganizationFormProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="organizations_path"
        onSubmit={updateField}
        label={t_i18n('Path in token')}
        style={fieldSpacingContainerStyle}
        fullWidth
      />
      {selectedStrategy === 'OpenID' && (
        <>
          <Field
            component={TextField}
            variant="standard"
            name="organizations_scope"
            onSubmit={updateField}
            label="Organizations scope"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
          <Field
            component={TextField}
            variant="standard"
            name="organizations_token_reference"
            onSubmit={updateField}
            label="Access token"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
        </>
      )}
      <FieldArray name="organizations_mapping">
        {({ push, remove, form }) => (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                marginTop: 20,
              }}
            >
              <Typography variant="h2">{t_i18n('Add a new value')}</Typography>
              <IconButton
                size="default"
                color="secondary"
                aria-label={t_i18n('Add a new value')}
                style={{ marginBottom: 12 }}
                onClick={() => push('')}
              >
                <Add fontSize="small" color="primary" />
              </IconButton>
            </div>
            {form.values.organizations_mapping
              && form.values.organizations_mapping.map(
                (value: string, index: number) => (
                  <div
                    key={index}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginBottom: 8,
                    }}
                  >
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`organizations_mapping[${index}]`}
                      label={t_i18n('Value organizations mappings')}
                      onSubmit={() => updateField('organizations_mapping', form.values.organizations_mapping)}
                      fullWidth
                      style={fieldSpacingContainerStyle}
                    />
                    {/* <div */}
                    {/*  style={{ flexBasis: '70%', maxWidth: '70%' }} */}
                    {/* > */}
                    {/*  <ObjectOrganizationField */}
                    {/*    outlined={false} */}
                    {/*    name="objectOrganization" */}
                    {/*    label="Organizations" */}
                    {/*    containerstyle={{ width: '100%' }} */}
                    {/*    style={fieldSpacingContainerStyle} */}
                    {/*    fullWidth */}
                    {/*  /> */}
                    {/* </div> */}
                    <IconButton
                      color="primary"
                      aria-label={t_i18n('Delete')}
                      style={{ marginTop: 30, marginLeft: 50 }}
                      onClick={() => {
                        remove(index);
                        const organizationsMapping = [...form.values.organizations_mapping];
                        organizationsMapping.splice(index, 1);
                        updateField('organizations_mapping', organizationsMapping);
                      }}
                    >
                      <Delete fontSize="small" />
                    </IconButton>
                  </div>
                ),
              )}
          </>
        )}
      </FieldArray>
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="organizations_read_userinfo"
        onChange={updateField}
        label={t_i18n('Automatically add users to default groups')}
        containerstyle={{ marginLeft: 2, marginTop: 30 }}
      />
    </>
  );
};

export default SSODefinitionOrganizationForm;
