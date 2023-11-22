import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Link } from 'react-router-dom';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import EEPaper from '@components/common/entreprise_edition/EEPaper';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { SettingsQuery$data } from '../__generated__/SettingsQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';

const SettingsAnalyticsValidation = () => Yup.object().shape({
  analytics_google_analytics_v4: Yup.string().nullable(),
});

interface SettingsAnalyticsProps {
  settings: SettingsQuery$data['settings'] & {
    readonly id: string;
  };
  handleChangeFocus: (id: string, name: string) => void;
  handleSubmitField: (id: string, name: string, value: unknown) => void;
  isEnterpriseEdition: boolean;
}

const SettingsAnalytics: FunctionComponent<SettingsAnalyticsProps> = ({
  settings,
  handleChangeFocus,
  handleSubmitField,
  isEnterpriseEdition,
}) => {
  const { t } = useFormatter();
  const { id, editContext } = settings;
  return (
    <>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t('Third-party analytics')}
        <EEChip />
      </Typography>
      <div style={{ float: 'left', margin: '-3px 0 0 10px' }}>
        <Tooltip
          title={
            <>
              {t('If needed, you can set a')}{' '}
              <Link
                to={'/dashboard/settings/accesses/policies'}
                target="_blank"
              >
                {t('consent message')}
              </Link>{' '}
              {t('on user login.')}
            </>
          }
        >
          <InformationOutline fontSize="small" color="primary" />
        </Tooltip>
      </div>
      <div className="clearfix" />
      <EEPaper variant="outlined">
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
                    label={t('Google Analytics (v4)')}
                    placeholder={t('G-XXXXXXXXXX')}
                    InputLabelProps={{
                      shrink: true,
                    }}
                    fullWidth
                    onFocus={(name: string) => handleChangeFocus(id, name)}
                    onSubmit={(name: string, value: string | null) => handleSubmitField(id, name, value)
                    }
                    disabled={!isEnterpriseEdition}
                    variant="standard"
                    helperText={
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="analytics_google_analytics_v4"
                      />
                    }
                  />
                </span>
              </EETooltip>
            </Form>
          )}
        </Formik>
      </EEPaper>
    </>
  );
};

export default SettingsAnalytics;
