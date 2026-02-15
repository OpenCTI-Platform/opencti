import React, { Suspense } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { AuthenticationGlobalSettingsQuery } from './__generated__/AuthenticationGlobalSettingsQuery.graphql';

const authenticationGlobalSettingsQuery = graphql`
  query AuthenticationGlobalSettingsQuery {
    settings {
      id
      otp_mandatory
      platform_session_max_concurrent
    }
  }
`;

const authenticationGlobalSettingsMutation = graphql`
  mutation AuthenticationGlobalSettingsMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        otp_mandatory
        platform_session_max_concurrent
      }
    }
  }
`;

const validationSchema = Yup.object().shape({
  otp_mandatory: Yup.boolean(),
  platform_session_max_concurrent: Yup.number().nullable(),
});

const AuthenticationGlobalSettingsContent = () => {
  const { t_i18n } = useFormatter();

  const data = useLazyLoadQuery<AuthenticationGlobalSettingsQuery>(authenticationGlobalSettingsQuery, {});
  const settings = data.settings;

  const [commitField] = useApiMutation(authenticationGlobalSettingsMutation);

  const handleSubmitField = (name: string, value: string | boolean) => {
    validationSchema
      .validateAt(name, { [name]: value })
      .then(() => {
        commitField({
          variables: {
            id: settings.id,
            input: {
              key: name,
              value: value !== '' ? value : '0',
            },
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    otp_mandatory: settings.otp_mandatory ?? false,
    platform_session_max_concurrent: settings.platform_session_max_concurrent ?? 0,
  };

  return (
    <Formik
      enableReinitialize
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={() => {}}
    >
      <Form>
        <Grid container spacing={3} style={{ marginBottom: 20 }}>
          <Grid item xs={6}>
            <Card title={t_i18n('Two-factor authentication')}>
              <Field
                component={SwitchField}
                type="checkbox"
                name="otp_mandatory"
                label={t_i18n('Enforce two-factor authentication')}
                onChange={(name: string, value: string) => handleSubmitField(name, value)}
                tooltip={t_i18n(
                  'When enforcing 2FA authentication, all users will be asked to enable 2FA to be able to login in the platform.',
                )}
              />
            </Card>
          </Grid>
          <Grid item xs={6}>
            <Card title={t_i18n('Sessions')}>
              <Field
                component={TextField}
                type="number"
                variant="standard"
                inputProps={{ min: 0 }}
                name="platform_session_max_concurrent"
                label={t_i18n('Max concurrent sessions (0 equals no maximum)')}
                fullWidth
                onSubmit={(name: string, value: string) => handleSubmitField(name, value !== '' ? value : '0')}
              />
            </Card>
          </Grid>
        </Grid>
      </Form>
    </Formik>
  );
};

const AuthenticationGlobalSettings = () => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <AuthenticationGlobalSettingsContent />
  </Suspense>
);

export default AuthenticationGlobalSettings;
