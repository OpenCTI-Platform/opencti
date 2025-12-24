import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Link } from 'react-router-dom';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { Stack } from '@mui/material';
import { SettingsQuery$data } from '../__generated__/SettingsQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import Card from '../../../../components/common/card/Card';

const SettingsAnalyticsValidation = () => Yup.object().shape({
  analytics_google_analytics_v4: Yup.string().nullable(),
});

interface SettingsAnalyticsProps {
  settings: SettingsQuery$data['settings'] & {
    readonly id: string;
  };
  handleChangeFocus: (id: string, name: string) => void;
  handleSubmitField: (id: string, name: string, value: string | null) => void;
  isEnterpriseEdition: boolean;
}

const SettingsAnalytics: FunctionComponent<SettingsAnalyticsProps> = ({
  settings,
  handleChangeFocus,
  handleSubmitField,
  isEnterpriseEdition,
}) => {
  const { t_i18n } = useFormatter();
  const { id, editContext } = settings;

  const title = (
    <Stack direction="row" alignItems="center" gap={1}>
      {t_i18n('Third-party analytics')}

      <Stack direction="row" gap={1}>
        <EEChip />
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
            style={{ paddingBottom: 2, paddingTop: 2 }}
          />
        </Tooltip>
      </Stack>
    </Stack>
  );

  return (
    <>

      <Card title={title}>
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
                    InputLabelProps={{
                      shrink: true,
                    }}
                    fullWidth
                    onFocus={(name: string) => handleChangeFocus(id, name)}
                    onSubmit={(name: string, value: string | null) => handleSubmitField(id, name, value)
                    }
                    disabled={!isEnterpriseEdition}
                    variant="standard"
                    helperText={(
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="analytics_google_analytics_v4"
                      />
                    )}
                  />
                </span>
              </EETooltip>
            </Form>
          )}
        </Formik>
      </Card>
    </>
  );
};

export default SettingsAnalytics;
