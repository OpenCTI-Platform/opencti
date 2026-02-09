import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import TextField from '../../../../components/TextField';

interface LDAPConfigProps {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
}

const LDAPConfig = ({ updateField }: LDAPConfigProps) => {
  const { t_i18n } = useFormatter();

  // Labels are not translated because they are technical terms localised in SSO.
  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="url"
        label="URL"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="bindDN"
        label="Bind DN"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="bindCredentials"
        label="Bind credentials"
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
        type="password"
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchBase"
        label="Search base"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchFilter"
        label="Search filter"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchBase"
        label="Group search base"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchFilter"
        label="Group search filter"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="allow_self_signed"
        required
        label={t_i18n('Allow self signed')}
        onChange={updateField}
        containerstyle={{ marginLeft: 2, marginTop: 10 }}
      />
    </>
  );
};

export default LDAPConfig;
