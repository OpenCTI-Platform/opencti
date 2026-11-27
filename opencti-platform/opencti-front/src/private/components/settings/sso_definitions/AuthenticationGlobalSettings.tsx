import React, { Suspense } from 'react';
import { Field, Form, Formik, useFormikContext } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import { Alert } from '@filigran/design-system';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { AuthenticationGlobalSettingsQuery } from './__generated__/AuthenticationGlobalSettingsQuery.graphql';
import { formatSessionMaxLifetime } from './sessionMaxLifetimeUtils';

const authenticationGlobalSettingsQuery = graphql`
  query AuthenticationGlobalSettingsQuery {
    settings {
      id
      otp_mandatory
      platform_session_max_concurrent
      platform_session_max_lifetime
      platform_session_presence_enabled
      platform_session_presence_manager_enabled
      platform_session_presence_supported
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
        platform_session_presence_enabled
      }
    }
  }
`;

const validationSchema = Yup.object().shape({
  otp_mandatory: Yup.boolean(),
  platform_session_max_concurrent: Yup.number().nullable(),
  platform_session_presence_enabled: Yup.boolean(),
});

// The logout when the last tab is closed can be enabled while it cannot apply:
// - the session presence manager, which logs the sessions out, is disabled on every node
// - with sessions held in the memory of each node, several nodes serve the API
const SessionPresenceAlerts = ({ isManagerEnabled, isSupported }: { isManagerEnabled: boolean; isSupported: boolean }) => {
  const { t_i18n } = useFormatter();
  const { values } = useFormikContext<{ platform_session_presence_enabled: boolean }>();
  if (!values.platform_session_presence_enabled) {
    return null;
  }
  return (
    <>
      {!isManagerEnabled && (
        <Alert
          severity="warning"
          style={{ marginTop: 20 }}
          title={t_i18n('The session presence manager is disabled on every platform node: no session is logged out when its last tab is closed.')}
        />
      )}
      {!isSupported && (
        <Alert
          severity="warning"
          style={{ marginTop: 20 }}
          title={t_i18n('Several platform nodes serve the API: no session is logged out when its last tab is closed.')}
        />
      )}
    </>
  );
};

const AuthenticationGlobalSettingsContent = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();

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
    // Comes from the platform configuration: only displayed
    platform_session_max_lifetime: formatSessionMaxLifetime(settings.platform_session_max_lifetime ?? 0, t_i18n),
    platform_session_presence_enabled: settings.platform_session_presence_enabled,
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
          <Grid size={6}>
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
          <Grid size={6}>
            <Card title={t_i18n('Sessions')}>
              <Field
                component={TextField}
                type="number"
                variant="outlined"
                min={0}
                name="platform_session_max_concurrent"
                label={t_i18n('Max concurrent sessions (0 equals no maximum)')}
                fullWidth
                onSubmit={(name: string, value: string) => handleSubmitField(name, value !== '' ? value : '0')}
              />
              <Field
                component={TextField}
                variant="outlined"
                name="platform_session_max_lifetime"
                label={t_i18n('Maximum session lifetime')}
                disabled
                fullWidth
                style={{ marginTop: 20 }}
                helperText={t_i18n('Set in the platform configuration (app:session_max_lifetime). When a session reaches it, its user must log in again, even when active.')}
              />
              {isFeatureEnable('SESSION_PRESENCE') && (
                <>
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="platform_session_presence_enabled"
                    label={t_i18n('Logout when the last tab is closed')}
                    containerstyle={{ marginTop: 20 }}
                    onChange={(name: string, value: string) => handleSubmitField(name, value)}
                    tooltip={t_i18n(
                      'When enabled, a session is logged out shortly after its last browser tab has been closed.',
                    )}
                  />
                  <SessionPresenceAlerts
                    isManagerEnabled={settings.platform_session_presence_manager_enabled}
                    isSupported={settings.platform_session_presence_supported}
                  />
                </>
              )}
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
