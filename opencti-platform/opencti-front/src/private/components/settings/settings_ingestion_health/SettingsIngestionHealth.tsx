import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Card from '../../../../components/common/card/Card';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { SettingsIngestionHealth_settings$key } from './__generated__/SettingsIngestionHealth_settings.graphql';

const settingsIngestionHealthFragment = graphql`
  fragment SettingsIngestionHealth_settings on Settings {
    id
    ingestion_health_settings {
      notification_delay
    }
  }
`;

const settingsIngestionHealthFieldPatch = graphql`
  mutation SettingsIngestionHealthFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        ...SettingsIngestionHealth_settings
      }
    }
  }
`;

const MINUTE_MS = 60 * 1000;
// Same bound as the backend: one day
const MAX_NOTIFICATION_DELAY_MINUTES = 24 * 60;

interface SettingsIngestionHealthProps {
  settings: SettingsIngestionHealth_settings$key;
}

// The delay is stored in ms and edited in minutes
const SettingsIngestionHealth = ({ settings }: SettingsIngestionHealthProps) => {
  const { t_i18n } = useFormatter();
  const { id, ingestion_health_settings } = useFragment(settingsIngestionHealthFragment, settings);
  const [commitField] = useApiMutation(settingsIngestionHealthFieldPatch);

  const validation = Yup.object().shape({
    notification_delay: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .integer(t_i18n('The value must be an integer'))
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(MAX_NOTIFICATION_DELAY_MINUTES, t_i18n('The value must be less than or equal to 1440'))
      .required(t_i18n('This field is required')),
  });

  const handleSubmitDelay = (name: string, value: string) => {
    validation.validateAt(name, { [name]: value }).then(() => {
      commitField({
        variables: {
          id,
          // The whole object is sent: the backend replaces it
          input: { key: 'ingestion_health_settings', value: { notification_delay: Number(value) * MINUTE_MS } },
        },
      });
    }).catch(() => false);
  };

  return (
    <Card title={t_i18n('Ingestion health')} data-testid="settings-ingestion-health">
      <Formik
        onSubmit={() => {}}
        enableReinitialize={true}
        initialValues={{ notification_delay: Math.round((ingestion_health_settings?.notification_delay ?? 0) / MINUTE_MS) }}
        validationSchema={validation}
      >
        {() => (
          <Form>
            <Field
              component={TextField}
              variant="outlined"
              type="number"
              name="notification_delay"
              label={t_i18n('Notification delay (in minutes)')}
              helperText={t_i18n('Time a health status must stay unchanged before it is notified')}
              fullWidth
              onSubmit={handleSubmitDelay}
            />
          </Form>
        )}
      </Formik>
    </Card>
  );
};

export default SettingsIngestionHealth;
