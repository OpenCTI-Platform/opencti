import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import { useFormatter } from '../../../../components/i18n';
import { Field } from 'formik';
import TextField from '../../../../components/TextField';
import React from 'react';

interface CERTConfigProps {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
}

const CERTConfig = ({ updateField }: CERTConfigProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="description"
        onSubmit={updateField}
        label={t_i18n('Description')}
        fullWidth
        style={{ marginTop: 20 }}
      />
    </>
  );
};

export default CERTConfig;
