import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Link } from 'react-router';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { Stack } from '@mui/material';
import { SettingsQuery$data } from '../__generated__/SettingsQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { useSubscriptionFocusHelper } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import SettingsOverline from '../settings_platform/SettingsOverline';

const SettingsAnalyticsValidation = () => Yup.object().shape({
  analytics_google_analytics_v4: Yup.string().nullable(),
});

interface SettingsAnalyticsProps {
  settings: SettingsQuery$data['settings'] & {
    readonly id: string;
  };
  handleChangeFocus: (name: string) => void;
  handleSubmitField: (name: string, value: string) => void;
  isEnterpriseEdition: boolean;
}

// Rendered inside the Configuration card of the Parameters page, as its last section.
const SettingsAnalytics: FunctionComponent<SettingsAnalyticsProps> = ({
  settings,
  handleChangeFocus,
  handleSubmitField,
  isEnterpriseEdition,
}) => {
  const { t_i18n } = useFormatter();
  const { editContext } = settings;
  const focusHelper = useSubscriptionFocusHelper(editContext);

  const adornment = (
    <Stack direction="row" alignItems="center" gap={1}>
      <EEChip size="sm" />
      <Tooltip
        title={(
          <>
            {t_i18n('If needed, you can set a')}{' '}
            <Link
              to="/dashboard/settings/accesses/policies"
              target="_blank"
            >
              {t_i18n('consent message')}
            </Link>{' '}
            {t_i18n('on user login.')}
          </>
        )}
      >
        <InformationOutline
          fontSize="small"
          color="primary"
        />
      </Tooltip>
    </Stack>
  );

  return (
    <section data-testid="settings-analytics">
      <SettingsOverline adornment={adornment}>{t_i18n('Third-party analytics')}</SettingsOverline>
      <Formik
        onSubmit={() => {}}
        enableReinitialize={true}
        initialValues={settings}
        validationSchema={SettingsAnalyticsValidation()}
      >
        {() => (
          <Form>
            <EETooltip>
              <span>
                <Field
                  component={TextField}
                  name="analytics_google_analytics_v4"
                  label={t_i18n('Google Analytics (v4)')}
                  placeholder={t_i18n('G-XXXXXXXXXX')}
                  fullWidth
                  onFocus={(name: string) => handleChangeFocus(name)}
                  onSubmit={(name: string, value: string | null) => handleSubmitField(name, value ?? '')}
                  disabled={!isEnterpriseEdition}
                  variant="outlined"
                  helperText={focusHelper('analytics_google_analytics_v4')}
                />
              </span>
            </EETooltip>
          </Form>
        )}
      </Formik>
    </section>
  );
};

export default SettingsAnalytics;
