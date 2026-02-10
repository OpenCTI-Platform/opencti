import { Field } from 'formik';
import TextField from 'src/components/TextField';
import React from 'react';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import { useFormatter } from 'src/components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SwitchField from '../../../../components/fields/SwitchField';
import GroupAndOrganizationMapping from './mapping/GroupAndOrganizationMapping';

type SSODefinitionGroupFormProps = {
  isEditionMode: boolean;
  selectedStrategy: string | null;
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
};

const SSODefinitionGroupForm = ({ isEditionMode, selectedStrategy, updateField }: SSODefinitionGroupFormProps) => {
  const { t_i18n } = useFormatter();

  const getGroupAttributeKeyName = () => {
    let name = null;
    if (selectedStrategy === 'SAML') name = 'group_attributes';
    if (selectedStrategy === 'OpenID') name = 'groups_attributes';
    if (selectedStrategy === 'LDAP') name = 'group_attribute';

    if (!name) return null;

    const helperText = selectedStrategy !== 'LDAP'
      ? t_i18n('Please add square bracket & each value between single quotes (even for unique value). For example: [\'value1\', \'value2\']')
      : null;

    return (
      <Field
        component={TextField}
        variant="standard"
        name={name}
        onSubmit={updateField}
        label={t_i18n('Attribute in token')}
        style={fieldSpacingContainerStyle}
        fullWidth
        helperText={helperText}
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
      <GroupAndOrganizationMapping
        isEditionMode={isEditionMode}
        label={t_i18n('Group mapping value')}
        name="groups_mapping"
        updateField={updateField}
      />
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
