import { Field } from 'formik';
import TextField from 'src/components/TextField';
import React from 'react';
import { useFormatter } from 'src/components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SwitchField from '../../../../components/fields/SwitchField';
import GroupAndOrganizationMapping from './mapping/GroupAndOrganizationMapping';

type SSODefinitionGroupFormProps = {
  selectedStrategy: string | null;
};

const SSODefinitionGroupForm = ({ selectedStrategy }: SSODefinitionGroupFormProps) => {
  const { t_i18n } = useFormatter();

  const getGroupAttributeKeyName = () => {
    let name = null;
    if (selectedStrategy === 'SAML') name = 'group_attributes';
    if (selectedStrategy === 'OpenID') name = 'groups_attributes';
    if (selectedStrategy === 'LDAP') name = 'group_attribute';

    if (!name) return null;

    const helperText = selectedStrategy !== 'LDAP'
      ? t_i18n('Please add square bracket & each value between double quotes (even for unique value). For example: ["value1", "value2"]')
      : null;

    return (
      <Field
        component={TextField}
        variant="standard"
        name={name}
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
            label="Group path"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
          <Field
            component={TextField}
            variant="standard"
            name="groups_scope"
            label="Group scope"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
          <Field
            component={TextField}
            variant="standard"
            name="groups_token_reference"
            label="Access token"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
        </>
      )}
      <GroupAndOrganizationMapping
        label={t_i18n('Group mapping value')}
        name="groups_mapping"
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="groups_read_userinfo"
        label={t_i18n('Automatically add users to default groups')}
        containerstyle={{ marginLeft: 2, marginTop: 30 }}
      />
    </>
  );
};

export default SSODefinitionGroupForm;
