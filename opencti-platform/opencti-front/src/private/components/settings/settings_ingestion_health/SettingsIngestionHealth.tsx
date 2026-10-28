import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Box from '@mui/material/Box';
import { Chip, Switch } from '@filigran/design-system';
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
      disabled_health_checks
      health_checks {
        health_check_code
        health_check_label
        health_check_kind
        health_check_severity
        enabled
      }
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
  const [commitField, isSaving] = useApiMutation(settingsIngestionHealthFieldPatch);
  const notificationDelay = ingestion_health_settings?.notification_delay ?? 0;
  const disabledHealthChecks = ingestion_health_settings?.disabled_health_checks ?? [];

  const validation = Yup.object().shape({
    notification_delay: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .integer(t_i18n('The value must be an integer'))
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(MAX_NOTIFICATION_DELAY_MINUTES, t_i18n('The value must be less than or equal to 1440'))
      .required(t_i18n('This field is required')),
  });

  // The whole object is sent: the backend replaces it, built on the last response.
  // The form is disabled while a save is in flight: an edit cannot be built on settings about to change and overwrite the save
  const commitSettings = (changes: { notification_delay?: number; disabled_health_checks?: readonly string[] }) => {
    commitField({
      variables: {
        id,
        input: {
          key: 'ingestion_health_settings',
          value: { notification_delay: notificationDelay, disabled_health_checks: disabledHealthChecks, ...changes },
        },
      },
    });
  };

  const handleSubmitDelay = (name: string, value: string) => {
    validation.validateAt(name, { [name]: value })
      .then(() => commitSettings({ notification_delay: Number(value) * MINUTE_MS }))
      .catch(() => false);
  };

  const handleToggleCheck = (code: string, enabled: boolean) => {
    const others = disabledHealthChecks.filter((disabledCode) => disabledCode !== code);
    commitSettings({ disabled_health_checks: enabled ? others : [...others, code] });
  };

  return (
    <Card title={t_i18n('Ingestion health monitoring')} data-testid="settings-ingestion-health">
      <Formik
        onSubmit={() => {}}
        enableReinitialize={true}
        initialValues={{ notification_delay: Math.round(notificationDelay / MINUTE_MS) }}
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
              disabled={isSaving}
              onSubmit={handleSubmitDelay}
            />
          </Form>
        )}
      </Formik>
      <Box component="h4" sx={{ marginTop: 3, marginBottom: 2 }}>{t_i18n('Health checks')}</Box>
      {/* 20px between the toggles, as between the switches of the group edition form */}
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr auto auto', alignItems: 'center', columnGap: 2, rowGap: '20px' }}>
        {[...(ingestion_health_settings?.health_checks ?? [])]
          // Configuration checks first, then runtime ones; by translated label within each kind
          .sort((a, b) => Number(a.health_check_kind === 'runtime') - Number(b.health_check_kind === 'runtime')
            || t_i18n(a.health_check_label).localeCompare(t_i18n(b.health_check_label)))
          .map((check) => {
            // A failing blocking check makes the ingestion critical, an advisory one degraded: same chips as the health status
            const isBlocking = check.health_check_severity === 'blocking';
            return (
              <Box
                key={check.health_check_code}
                data-testid={`settings-ingestion-health-check-${check.health_check_code}`}
                sx={{ display: 'contents' }}
              >
                <Box sx={{ minWidth: 0 }}>
                  <Switch
                    checked={check.enabled}
                    disabled={isSaving}
                    onCheckedChange={(enabled) => handleToggleCheck(check.health_check_code, enabled)}
                    // Named by the backend registry, translated with the labels of the backend schema
                    label={t_i18n(check.health_check_label)}
                  />
                </Box>
                {/* Centered in their column: the column is as wide as its longest value */}
                <Box component="span" sx={{ justifySelf: 'center', textAlign: 'center', fontSize: 12, color: 'text.secondary' }}>
                  {check.health_check_kind === 'runtime' ? t_i18n('Runtime') : t_i18n('Configuration')}
                </Box>
                {/* Further apart from the kind than the gap of the grid: same padding on every row, the chips stay aligned */}
                <Box sx={{ justifySelf: 'center', display: 'flex', paddingLeft: 3 }}>
                  <Chip
                    label={isBlocking ? t_i18n('Blocking') : t_i18n('Degraded')}
                    severity={isBlocking ? 'critical' : 'high'}
                  />
                </Box>
              </Box>
            );
          })}
      </Box>
    </Card>
  );
};

export default SettingsIngestionHealth;
