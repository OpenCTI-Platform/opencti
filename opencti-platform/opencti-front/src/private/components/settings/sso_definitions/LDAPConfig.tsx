import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { Stack } from '@mui/material';

const LDAPConfig = () => {
  const { t_i18n } = useFormatter();

  // Labels are not translated because they are technical terms localised in SSO.
  return (
    <Stack gap={2}>
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
      />
      <Field
        component={TextField}
        variant="standard"
        name="bindCredentials"
        label="Bind credentials"
        fullWidth
        type="password"
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchBase"
        label="Search base"
        required
        fullWidth
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchFilter"
        label="Search filter"
        required
        fullWidth
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchBase"
        label="Group search base"
        required
        fullWidth
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchFilter"
        label="Group search filter"
        required
        fullWidth
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="allow_self_signed"
        required
        label={t_i18n('Allow self signed')}
        containerstyle={{ marginLeft: 2 }}
      />
    </Stack>
  );
};

export default LDAPConfig;
