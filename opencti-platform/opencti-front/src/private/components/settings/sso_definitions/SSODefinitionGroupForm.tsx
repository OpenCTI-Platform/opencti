import { Field, FieldArray } from 'formik';
import TextField from 'src/components/TextField';
import React from 'react';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Add, Delete } from '@mui/icons-material';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import { useFormatter } from 'src/components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SwitchField from '../../../../components/fields/SwitchField';

type SSODefinitionGroupFormProps = {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
  selectedStrategy: string | null;
};

const SSODefinitionGroupForm = ({ updateField, selectedStrategy }: SSODefinitionGroupFormProps) => {
  const { t_i18n } = useFormatter();

  const getGroupAttributeKeyName = () => {
    let name = null;
    if (selectedStrategy === 'SAML') name = 'group_attributes';
    if (selectedStrategy === 'OpenID') name = 'groups_attributes';
    if (selectedStrategy === 'LDAP') name = 'group_attribute';

    if (!name) return null;

    return (
      <Field
        component={TextField}
        variant="standard"
        name={name}
        onSubmit={updateField}
        label={t_i18n('Attribute in token')}
        style={fieldSpacingContainerStyle}
        fullWidth
      />
    );
  };

  return (
    <>
      {getGroupAttributeKeyName()}
      {selectedStrategy === 'OpenID' && (
        <>
          <Field
            component={TextField}
            variant="standard"
            name="groups_path"
            onSubmit={updateField}
            label="Group path"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
          <Field
            component={TextField}
            variant="standard"
            name="groups_scope"
            onSubmit={updateField}
            label="Group scope"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
          <Field
            component={TextField}
            variant="standard"
            name="groups_token_reference"
            onSubmit={updateField}
            label="Access token"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
        </>
      )}
      <FieldArray name="groups_mapping">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
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
            {form.values.groups_mapping
              && form.values.groups_mapping.map(
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
                      onSubmit={() => updateField('groups_mapping', form.values.groups_mapping)}
                      name={`groups_mapping[${index}]`}
                      label={t_i18n('Group mapping value')}
                      fullWidth
                      style={fieldSpacingContainerStyle}
                    />
                    {/* <div */}
                    {/*  style={{ */}
                    {/*    flexBasis: '70%', */}
                    {/*    maxWidth: '70%', */}
                    {/*    marginBottom: 20, */}
                    {/*  }} */}
                    {/* > */}
                    {/*  <GroupField */}
                    {/*    name="groups" */}
                    {/*    label="Groups" */}
                    {/*    style={fieldSpacingContainerStyle} */}
                    {/*    showConfidence={true} */}
                    {/*  /> */}
                    {/* </div> */}
                    <IconButton

                      color="primary"
                      aria-label={t_i18n('Delete')}
                      style={{ marginTop: 30, marginLeft: 50 }}
                      onClick={() => {
                        const groupsMapping = [...form.values.groups_mapping];
                        groupsMapping.splice(index, 1);
                        remove(index);
                        updateField('groups_mapping', groupsMapping);
                      }} // Delete
                    >
                      <Delete fontSize="small" />
                    </IconButton>
                    {/* <Field */}
                    {/*  component={SwitchField} */}
                    {/*  variant="standard" */}
                    {/*  type="checkbox" */}
                    {/*  name="auto_create_group" */}
                    {/*  label={t_i18n('auto-create group')} */}
                    {/*  containerstyle={{ marginTop: 10 }} */}
                    {/* /> */}
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
        name="groups_read_userinfo"
        onChange={updateField}
        label={t_i18n('Automatically add users to default groups')}
        containerstyle={{ marginLeft: 2, marginTop: 30 }}
      />
    </>
  );
};

export default SSODefinitionGroupForm;
