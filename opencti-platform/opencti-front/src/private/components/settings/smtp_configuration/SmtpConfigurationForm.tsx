import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import Alert from '@mui/material/Alert';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import SwitchField from 'src/components/fields/SwitchField';
import SelectField from 'src/components/fields/SelectField';
import TextField from 'src/components/TextField';
import DateTimePickerField from 'src/components/DateTimePickerField';
import { useFormatter } from 'src/components/i18n';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { MESSAGING$ } from 'src/relay/environment';
import type { Theme } from 'src/components/Theme';
import type { SmtpConfigurationFormEditMutation } from './__generated__/SmtpConfigurationFormEditMutation.graphql';

export const smtpConfigurationEditMutation = graphql`
  mutation SmtpConfigurationFormEditMutation($input: SmtpConfigurationAddInput!) {
    smtpConfigurationEdit(input: $input) {
      smtp_enabled
      use_db_config
      sender_email_address
      hostname
      port
      use_ssl
      reject_unauthorized
      auth_type
      username
      oauth_user
      oauth_client_id
      oauth_issuer
      oauth_refresh_token_expires_at
    }
  }
`;

export interface SmtpConfigurationData {
  smtp_enabled?: boolean | null;
  use_db_config?: boolean | null;
  sender_email_address?: string | null;
  hostname?: string | null;
  port?: number | null;
  use_ssl?: boolean | null;
  reject_unauthorized?: boolean | null;
  auth_type?: string | null;
  username?: string | null;
  oauth_user?: string | null;
  oauth_client_id?: string | null;
  oauth_issuer?: string | null;
  oauth_refresh_token_expires_at?: string | null;
}

interface SmtpConfigurationFormProps {
  smtpConfiguration: SmtpConfigurationData | null;
  onCompleted: () => void;
  onCancel: () => void;
}

interface SmtpConfigurationFormValues {
  smtp_enabled: boolean;
  use_db_config: boolean;
  sender_email_address: string;
  hostname: string;
  port: number | '';
  use_ssl: boolean;
  reject_unauthorized: boolean;
  auth_type: 'basic' | 'oauth2';
  username: string;
  password: string;
  oauth_user: string;
  oauth_client_id: string;
  oauth_client_secret: string;
  oauth_issuer: string;
  oauth_refresh_token: string;
  oauth_refresh_token_expires_at: string | null;
}

// Secrets (password, oauth_client_secret, oauth_refresh_token) are never returned by the API,
// so they must be re-entered on every submit, matching the backend validation.
const validationSchema = Yup.object().shape({
  sender_email_address: Yup.string().email().nullable(),
  hostname: Yup.string().nullable(),
  port: Yup.number().nullable().notOneOf([25], 'Port 25 is not allowed for SMTP configuration'),
  auth_type: Yup.string().oneOf(['basic', 'oauth2']).required(),
  username: Yup.string().when('auth_type', {
    is: 'basic',
    then: (schema) => schema.required(),
  }),
  password: Yup.string().when('auth_type', {
    is: 'basic',
    then: (schema) => schema.required(),
  }),
  oauth_client_id: Yup.string().when('auth_type', {
    is: 'oauth2',
    then: (schema) => schema.required(),
  }),
  oauth_client_secret: Yup.string().when('auth_type', {
    is: 'oauth2',
    then: (schema) => schema.required(),
  }),
  oauth_issuer: Yup.string().when('auth_type', {
    is: 'oauth2',
    then: (schema) => schema.required(),
  }),
});

const SmtpConfigurationForm: FunctionComponent<SmtpConfigurationFormProps> = ({
  smtpConfiguration,
  onCompleted,
  onCancel,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [commitEdit] = useApiMutation<SmtpConfigurationFormEditMutation>(smtpConfigurationEditMutation);

  const initialValues: SmtpConfigurationFormValues = {
    smtp_enabled: smtpConfiguration?.smtp_enabled ?? false,
    use_db_config: smtpConfiguration?.use_db_config ?? false,
    sender_email_address: smtpConfiguration?.sender_email_address ?? '',
    hostname: smtpConfiguration?.hostname ?? '',
    port: smtpConfiguration?.port ?? '',
    use_ssl: smtpConfiguration?.use_ssl ?? false,
    reject_unauthorized: smtpConfiguration?.reject_unauthorized ?? true,
    auth_type: (smtpConfiguration?.auth_type as 'basic' | 'oauth2' | undefined) ?? 'basic',
    username: smtpConfiguration?.username ?? '',
    password: '',
    oauth_user: smtpConfiguration?.oauth_user ?? '',
    oauth_client_id: smtpConfiguration?.oauth_client_id ?? '',
    oauth_client_secret: '',
    oauth_issuer: smtpConfiguration?.oauth_issuer ?? '',
    oauth_refresh_token: '',
    oauth_refresh_token_expires_at: smtpConfiguration?.oauth_refresh_token_expires_at ?? null,
  };

  const buildInput = (values: SmtpConfigurationFormValues) => {
    const input: Record<string, unknown> = {
      smtp_enabled: values.smtp_enabled,
      use_db_config: values.use_db_config,
      sender_email_address: values.sender_email_address || null,
      hostname: values.hostname || null,
      port: values.port === '' ? null : Number(values.port),
      use_ssl: values.use_ssl,
      reject_unauthorized: values.reject_unauthorized,
      auth_type: values.auth_type,
    };
    if (values.auth_type === 'basic') {
      input.username = values.username || null;
      input.password = values.password;
    } else {
      input.oauth_user = values.oauth_user || null;
      input.oauth_client_id = values.oauth_client_id || null;
      input.oauth_client_secret = values.oauth_client_secret;
      input.oauth_issuer = values.oauth_issuer || null;
      if (values.oauth_refresh_token) {
        input.oauth_refresh_token = values.oauth_refresh_token;
      }
      input.oauth_refresh_token_expires_at = values.oauth_refresh_token_expires_at
        ? new Date(values.oauth_refresh_token_expires_at).toISOString()
        : null;
    }
    return input;
  };

  const handleSubmit = (
    values: SmtpConfigurationFormValues,
    { setSubmitting }: { setSubmitting: (isSubmitting: boolean) => void },
  ) => {
    const input = buildInput(values);
    commitEdit({
      variables: { input: input as SmtpConfigurationFormEditMutation['variables']['input'] },
      onCompleted: () => {
        setSubmitting(false);
        MESSAGING$.notifySuccess(t_i18n('SMTP configuration saved'));
        onCompleted();
      },
      onError: () => setSubmitting(false),
    });
  };

  return (
    <Formik<SmtpConfigurationFormValues>
      onSubmit={handleSubmit}
      onReset={onCancel}
      initialValues={initialValues}
      validationSchema={validationSchema}
    >
      {({ values, isSubmitting, handleReset, submitForm }) => (
        <Form>
          <Field
            component={SwitchField}
            type="checkbox"
            name="smtp_enabled"
            label={t_i18n('Enable email sending')}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="use_db_config"
            label={t_i18n('Use this configuration instead of the platform config file')}
          />
          {!values.use_db_config && (
            <Alert severity="info" variant="outlined" style={{ marginTop: 10, marginBottom: 10 }}>
              {t_i18n('The platform currently uses the SMTP configuration from the app-config file. Enable the option above to use the configuration below instead.')}
            </Alert>
          )}
          <Field
            component={TextField}
            variant="standard"
            name="sender_email_address"
            label={t_i18n('Sender email address')}
            fullWidth
            style={{ marginTop: 10 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="hostname"
            label={t_i18n('Hostname')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            type="number"
            name="port"
            label={t_i18n('Port')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="use_ssl"
            label={t_i18n('Use SSL/TLS')}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="reject_unauthorized"
            label={t_i18n('Reject unauthorized certificates')}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="auth_type"
            label={t_i18n('Authentication type')}
            fullWidth
            containerstyle={{ marginTop: 20, width: '100%' }}
          >
            <MenuItem value="basic">{t_i18n('Basic')}</MenuItem>
            <MenuItem value="oauth2">{t_i18n('OAuth2')}</MenuItem>
          </Field>
          {values.auth_type === 'basic' ? (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="username"
                label={t_i18n('Username')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                type="password"
                name="password"
                label={t_i18n('Password')}
                fullWidth
                style={{ marginTop: 20 }}
              />
            </>
          ) : (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="oauth_user"
                label={t_i18n('OAuth user')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="oauth_client_id"
                label={t_i18n('OAuth client ID')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                type="password"
                name="oauth_client_secret"
                label={t_i18n('OAuth client secret')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="oauth_issuer"
                label={t_i18n('OAuth issuer')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                type="password"
                name="oauth_refresh_token"
                label={t_i18n('OAuth refresh token')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={DateTimePickerField}
                name="oauth_refresh_token_expires_at"
                textFieldProps={{
                  label: t_i18n('Refresh token expiration date'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
            </>
          )}
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Save')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default SmtpConfigurationForm;
