import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Box from '@mui/material/Box';
import { Switch } from '@filigran/design-system';
import EEChip from '@components/common/entreprise_edition/EEChip';
import Card from '../../../../components/common/card/Card';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { SettingsIngestionHealth_settings$key } from './__generated__/SettingsIngestionHealth_settings.graphql';
import { SettingsIngestionHealthEditMutation, IngestionHealthSettingsInput } from './__generated__/SettingsIngestionHealthEditMutation.graphql';

const settingsIngestionHealthFragment = graphql`
  fragment SettingsIngestionHealth_settings on IngestionHealthSettings {
      notification_delay
      disabled_health_checks
      health_checks {
        health_check_code
        health_check_label
        health_check_kind
        enabled
      
    }
  }
`;

const settingsIngestionHealthEdit = graphql`
  mutation SettingsIngestionHealthEditMutation($input: IngestionHealthSettingsInput!) {
    ingestionHealthSettingsEdit(input: $input) {
      ...SettingsIngestionHealth_settings
    }
  }
`;

const MINUTE_MS = 60 * 1000;
// Same bound as the backend: one day
const MAX_NOTIFICATION_DELAY_MINUTES = 24 * 60;

interface SettingsIngestionHealthProps {
  // Query.ingestionHealthSettings: not part of the platform settings API
  settings: SettingsIngestionHealth_settings$key | null | undefined;
}

// The delay is stored in ms and edited in minutes
const SettingsIngestionHealth = ({ settings }: SettingsIngestionHealthProps) => {
  const { t_i18n } = useFormatter();
  const ingestion_health_settings = useFragment(settingsIngestionHealthFragment, settings);
  const [commitEdit, isSaving] = useApiMutation<SettingsIngestionHealthEditMutation>(settingsIngestionHealthEdit);
  const isEnterpriseEdition = useEnterpriseEdition();
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

  // Only the changed field is sent, the backend keeps the other one.
  // The form is disabled while a save is in flight: the disabled checks are built on the last response
  const commitSettings = (input: IngestionHealthSettingsInput) => {
    commitEdit({
      variables: { input },
      // The edition returns the settings under its own root field: link them to the one read by the query
      updater: (store) => {
        const edited = store.getRootField('ingestionHealthSettingsEdit');
        if (edited) store.getRoot().setLinkedRecord(edited, 'ingestionHealthSettings');
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
              // Changing the delay is an EE feature since activity notifications are EE
              disabled={isSaving || !isEnterpriseEdition}
              infoTooltip={isEnterpriseEdition ? undefined : <EEChip feature="Notification delay" size="sm" />}
              onSubmit={handleSubmitDelay}
            />
          </Form>
        )}
      </Formik>
      <Box component="h4" sx={{ marginTop: 3, marginBottom: 2 }}>{t_i18n('Health checks')}</Box>
      {/* 20px between the toggles, as between the switches of the group edition form */}
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr auto', alignItems: 'center', columnGap: 2, rowGap: '20px' }}>
        {[...(ingestion_health_settings?.health_checks ?? [])]
          // Configuration checks first, then runtime ones; by translated label within each kind
          .sort((a, b) => Number(a.health_check_kind === 'runtime') - Number(b.health_check_kind === 'runtime')
            || t_i18n(a.health_check_label).localeCompare(t_i18n(b.health_check_label)))
          .map((check) => (
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
              {/* Centered in its column: the column is as wide as its longest value */}
              <Box component="span" sx={{ justifySelf: 'center', textAlign: 'center', fontSize: 12, color: 'text.secondary' }}>
                {check.health_check_kind === 'runtime' ? t_i18n('Runtime') : t_i18n('Configuration')}
              </Box>
            </Box>
          ))}
      </Box>
    </Card>
  );
};

export default SettingsIngestionHealth;
