import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { makeStyles } from '@mui/styles';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Link } from 'react-router-dom';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { SettingsQuery$data } from '../__generated__/SettingsQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
}));

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
  const classes = useStyles();
  const { id, editContext } = settings;
  return (
    <>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t('Third-party analytics')}
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
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Formik
          onSubmit={() => {}}
          enableReinitialize={true}
          initialValues={settings}
          validationSchema={SettingsAnalyticsValidation()}
        >
          {() => (
            <Form>
              <Tooltip
                title={
                  !isEnterpriseEdition
                    ? t(
                      'You need to activate OpenCTI enterprise edition to use this feature.',
                    )
                    : null
                }
              >
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
              </Tooltip>
            </Form>
          )}
        </Formik>
      </Paper>
    </>
  );
};

export default SettingsAnalytics;
