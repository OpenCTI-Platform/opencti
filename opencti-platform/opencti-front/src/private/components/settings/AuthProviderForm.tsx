import React, { FunctionComponent, useMemo } from 'react';
import Button from '@mui/material/Button';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { MenuItem } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Policies$data } from '@components/settings/__generated__/Policies.graphql';
import { JsonForms } from '@jsonforms/react';
import AuthProvidersSchemas from '@components/settings/AuthProvidersSchemas';
import { customRenderers } from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import SelectField from '../../../components/fields/SelectField';
import SwitchField from '../../../components/fields/SwitchField';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import type { Theme } from '../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import Alert from '@mui/material/Alert';
import { Accordion, AccordionSummary } from '../../../components/Accordion';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import { JsonSchema } from '@jsonforms/core';
import AuthProviderJsonForm from '@components/settings/AuthProviderJsonForm';

export type AuthProvider = Partial<Policies$data['platform_providers'][0]> & {
  isConfigFile?: boolean;
};

interface AuthProviderInput {
  identifier: string;
  strategy: string;
  disabled: boolean;
  config: string;
}

const providerValidation = Yup.object().shape({
  identifier: Yup.string().required(),
  strategy: Yup.string().required(),
  disabled: Yup.boolean(),
});

const AuthProviderForm: FunctionComponent<{
  provider?: AuthProvider;
  onClose: () => void;
  onCreate?: (provider: AuthProvider) => void;
  onUpdate?: (provider: AuthProvider) => void;
}> = ({ provider, onClose, onCreate, onUpdate }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const conf = JSON.parse(provider?.config || '{}');
  const initialValues = {
    identifier: provider?.identifier || '',
    strategy: provider?.strategy || 'OpenIDConnectStrategy',
    disabled: provider?.disabled ?? false,
    ...(typeof conf === 'string' ? JSON.parse(conf) : conf),
  };

  const handleSubmit: FormikConfig<AuthProviderInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const {
      identifier,
      disabled,
      strategy,
      ...config
    } = values;
    const newProvider = {
      identifier,
      disabled,
      strategy,
      config: JSON.stringify(config),
    };
    if (provider) {
      onUpdate?.(newProvider);
    } else {
      onCreate?.(newProvider);
    }
    setSubmitting(false);
    resetForm();
    onClose();
  };

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={providerValidation}
      onSubmit={handleSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, values, setFieldValue, setValues }) => {
        return (
          <Form>
            <Field
              component={TextField}
              name="identifier"
              label={t_i18n('Identifier')}
              fullWidth
              required
            />
            <Field
              component={SelectField}
              name="strategy"
              label={t_i18n('Strategy')}
              fullWidth
              required
              containerstyle={fieldSpacingContainerStyle}
              onChange={(name: string, value: string) => setFieldValue(name, value)}
            >
              <MenuItem value="OpenIDConnectStrategy">{t_i18n('OpenID Connect')}</MenuItem>
              <MenuItem value="SamlStrategy">{t_i18n('SAML')}</MenuItem>
              <MenuItem value="LdapStrategy">{t_i18n('LDAP')}</MenuItem>
            </Field>
            <Field
              component={SwitchField}
              type="checkbox"
              name="disabled"
              label={t_i18n('Disabled')}
              containerstyle={fieldSpacingContainerStyle}
            />

            {AuthProvidersSchemas[values.strategy] && (
              <AuthProviderJsonForm
                schema={AuthProvidersSchemas[values.strategy]}
                handleChange={async ({ data }) => {
                  console.log('Value ?', data);
                  await setValues({ ...values, ...data });
                }}
              />
            )}

            {values.strategy === 'SamlStrategy' && (
              <>
                <Field
                  component={TextField}
                  name="sso_url"
                  label={t_i18n('SSO URL')}
                  fullWidth
                  required
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={TextField}
                  name="issuer"
                  label={t_i18n('Issuer')}
                  fullWidth
                  required
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={TextField}
                  name="certificate"
                  label={t_i18n('Certificate')}
                  fullWidth
                  multiline
                  rows={4}
                  required
                  style={fieldSpacingContainerStyle}
                />
              </>
            )}

            <div
              style={{
                marginTop: 20,
                textAlign: 'right',
              }}
            >
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {provider ? t_i18n('Update') : t_i18n('Create')}
              </Button>
            </div>
          </Form>
        );
      }}
    </Formik>
  );
};

export default AuthProviderForm;
