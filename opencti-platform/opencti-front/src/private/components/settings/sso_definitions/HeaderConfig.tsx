import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import TextField from '../../../../components/TextField';

interface HeaderConfigProps {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
}

const HeaderConfig = ({ updateField }: HeaderConfigProps) => {
  const { t_i18n } = useFormatter();

  // Labels are not translated because they are technical terms localised in SSO.
  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="email"
        label="Email"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label="Name"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="firstname"
        label="First name"
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
        type="password"
      />
      <Field
        component={TextField}
        variant="standard"
        name="lastname"
        label="Last name"
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
    </>
  );
};

export default HeaderConfig;
