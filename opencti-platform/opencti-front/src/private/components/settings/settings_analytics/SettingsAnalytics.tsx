import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { makeStyles } from '@mui/styles';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Alert from '@mui/material/Alert';
import { Link } from 'react-router-dom';
import {
  SettingsQuery$data,
} from '../__generated__/SettingsQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    marginTop: theme.spacing(1.5),
    padding: theme.spacing(2),
    borderRadius: 6,
  },
}));

const SettingsAnalyticsValidation = () => Yup.object().shape({
  analytics_google_analytics_v4: Yup.string().nullable(),
});

interface SettingsAnalyticsProps {
  settings: SettingsQuery$data['settings'] & {
    readonly id: string
  }
  handleChangeFocus: (id: string, name: string) => void
  handleSubmitField: (id: string, name: string, value: unknown) => void
}

const SettingsAnalytics: FunctionComponent<SettingsAnalyticsProps> = ({
  settings,
  handleChangeFocus,
  handleSubmitField,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { id, editContext } = settings;

  return (
    <>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t('Analytics')}
      </Typography>
      <div className="clearfix" />
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
        style={{ marginTop: 0 }}
      >
        <Alert severity="info" style={{ marginBottom: 15 }}>
          {t(
            'Do not forget to update your',
          )}{' '}
          <Link to={'/dashboard/settings/accesses/policies'}>
            {t('consent message')}
          </Link>{' '}
          {t(
            'if needed',
          )}
        </Alert>
        <Formik
          onSubmit={() => {
          }}
          enableReinitialize={true}
          initialValues={settings}
          validationSchema={SettingsAnalyticsValidation()}
        >
          {() => (
            <Form>
              <Field
                component={TextField}
                name="analytics_google_analytics_v4"
                label={t('Google analytics (v4)')}
                placeholder={t('G-XXXXXXXXXX')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                onFocus={(name: string) => handleChangeFocus(id, name)}
                onSubmit={(name: string, value: string | null) => handleSubmitField(id, name, value)}
                variant="standard"
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="analytics_google_analytics_v4"
                  />
                }
              />
            </Form>
          )}
        </Formik>
      </Paper>
    </>
  );
};

export default SettingsAnalytics;
