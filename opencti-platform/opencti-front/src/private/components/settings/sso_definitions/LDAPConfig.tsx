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

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="url"
        label={t_i18n('URL')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="bindDN"
        label={t_i18n('Bind DN')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchBase"
        label={t_i18n('Search base')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="searchFilter"
        label={t_i18n('Search filter')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchBase"
        label={t_i18n('Group search filter')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="groupSearchFilter"
        label={t_i18n('Group search filter')}
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
