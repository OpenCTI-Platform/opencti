import React from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import { Add, Delete } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import SwitchField from '../../../../components/fields/SwitchField';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import TextField from '../../../../components/TextField';

interface LDAPConfigProps{
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
}

const LDAPConfig = ({ updateField }: LDAPConfigProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant='standard'
        name='searchFilter'
        label={t_i18n('Search filter')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant='standard'
        name='searchAttributes'
        label={t_i18n('Search attributes')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant='standard'
        name='searchBase' // search base dns
        label={t_i18n('Search base')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant='standard'
        name='bindDN'
        label={t_i18n('Bind dn')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant='standard'
        name='bindCredentials'
        label={t_i18n('Bind credentials')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant='standard'
        name='portNumber'
        label={t_i18n('Port number')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
    </>
  );
};

export default LDAPConfig;