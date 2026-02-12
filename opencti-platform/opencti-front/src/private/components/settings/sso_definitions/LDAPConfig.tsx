import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';

const LDAPConfig = () => {
  const { t_i18n } = useFormatter();

  // Labels are not translated because they are technical terms localised in SSO.
  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="url"
        label="URL"
        required
        fullWidth
      />
      <Field
        component={TextField}
        variant="standard"
        name="bindDN"
        label="Bind DN"
        required
        fullWidth
        style={{ marginTop: 16 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="bindCredentials"
        label="Bind credentials"
        fullWidth
        style={{ marginTop: 16 }}
        type="password"
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchBase"
        label="Search base"
        required
        fullWidth
        style={{ marginTop: 16 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchFilter"
        label="Search filter"
        required
        fullWidth
        style={{ marginTop: 16 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchBase"
        label="Group search base"
        required
        fullWidth
        style={{ marginTop: 16 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchFilter"
        label="Group search filter"
        required
        fullWidth
        style={{ marginTop: 16 }}
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="allow_self_signed"
        required
        label={t_i18n('Allow self signed')}
        containerstyle={{ marginLeft: 2, marginTop: 16 }}
      />
    </>
  );
};

export default LDAPConfig;
