import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { makeStyles } from '@mui/styles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import AccessesMenu from './AccessesMenu';
import ObjectOrganizationField from '../common/form/ObjectOrganizationField';
import { useFormatter } from '../../../components/i18n';
import { Option } from '../common/form/ReferenceField';
import SwitchField from '../../../components/SwitchField';
import TextField from '../../../components/TextField';
import useAuth from '../../../utils/hooks/useAuth';
import { AccessSettings$key } from './__generated__/AccessSettings.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

const accessSettingsFragment = graphql`
  fragment AccessSettings on Settings {
    id
    password_policy_min_length
    password_policy_min_symbols
    password_policy_min_numbers
    password_policy_min_words
    password_policy_min_lowercase
    password_policy_min_uppercase
    platform_organization {
      id
      name
    }
    otp_mandatory
  }
`;

export const accessSettingsFieldPatch = graphql`
  mutation AccessSettingsFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        ...AccessSettings
      }
    }
  }
`;

const settingsValidation = () => Yup.object().shape({
  platform_organization: Yup.object().nullable(),
  otp_mandatory: Yup.boolean(),
  password_policy_min_length: Yup.number(),
  password_policy_min_symbols: Yup.number(),
  password_policy_min_numbers: Yup.number(),
  password_policy_min_words: Yup.number(),
  password_policy_min_lowercase: Yup.number(),
  password_policy_min_uppercase: Yup.number(),
});

const AccessSettings: FunctionComponent = () => {
  const { settings: rawSettings } = useAuth();
  const settings = useFragment<AccessSettings$key>(accessSettingsFragment, rawSettings);
  const [commit] = useMutation(accessSettingsFieldPatch);
  const classes = useStyles();
  const { t } = useFormatter();
  const handleSubmitField = (name: string, value: unknown) => {
    settingsValidation().validateAt(name, { [name]: value }).then(() => {
      commit({ variables: { id: settings.id, input: { key: name, value: value || '' } } });
    }).catch(() => false);
  };
  const initialValues = {
    platform_organization: settings.platform_organization ? { label: settings.platform_organization?.name, value: settings.platform_organization?.id } : '',
    password_policy_min_length: settings.password_policy_min_length,
    password_policy_min_symbols: settings.password_policy_min_symbols,
    password_policy_min_numbers: settings.password_policy_min_numbers,
    password_policy_min_words: settings.password_policy_min_words,
    password_policy_min_lowercase: settings.password_policy_min_lowercase,
    password_policy_min_uppercase: settings.password_policy_min_uppercase,
  };
  return <div className={classes.container}>
    <AccessesMenu />
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={12}>
          <Formik onSubmit={() => {}} initialValues={initialValues} validationSchema={settingsValidation()}>
            {() => (
                <Form>
                  <div>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Organization')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <b>{t('When you specified the platform organization, data without any organization restriction will be accessible only for users that are part of the platform one')}</b>
                      <ObjectOrganizationField name="platform_organization" label={'Platform organization'}
                                               onChange={(name: string, value: Option) => handleSubmitField(name, value.value)}
                                               style={{ width: '100%', marginTop: 20 }} multiple={false} outlined={false}/>
                    </Paper>
                  </div>
                  <div style={{ marginTop: 20 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Two factor authentication')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Field component={SwitchField} type="checkbox" name="otp_mandatory"
                             label={t('Enforce two-factor authentication')}
                             onChange={(name: string, value: string) => handleSubmitField(name, value)}/>
                    </Paper>
                  </div>
                  <div style={{ marginTop: 20 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Local password policies')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Field component={TextField} type="number" variant="standard"
                          name="password_policy_min_length" label={t('Number of chars must be greater or equals to')} fullWidth={true}
                          onSubmit={(name: string, value: string) => {
                            return handleSubmitField(name, value !== '' ? value : '0');
                          }}
                      />
                      <Field component={TextField} type="number" variant="standard" style={{ marginTop: 20 }}
                             name="password_policy_min_symbols" label={t('Number of symbols must be greater or equals to')} fullWidth={true}
                             onSubmit={(name: string, value: string) => {
                               return handleSubmitField(name, value !== '' ? value : '0');
                             }}
                      />
                      <Field component={TextField} type="number" variant="standard" style={{ marginTop: 20 }}
                             name="password_policy_min_numbers" label={t('Number of digits must be greater or equals to')} fullWidth={true}
                             onSubmit={(name: string, value: string) => {
                               return handleSubmitField(name, value !== '' ? value : '0');
                             }}
                      />
                      <Field component={TextField} type="number" variant="standard" style={{ marginTop: 20 }}
                             name="password_policy_min_words" label={t('Number of words (split on hyphen, space) must be greater or equals to')} fullWidth={true}
                             onSubmit={(name: string, value: string) => {
                               return handleSubmitField(name, value !== '' ? value : '0');
                             }}
                      />
                      <Field component={TextField} type="number" variant="standard" style={{ marginTop: 20 }}
                             name="password_policy_min_lowercase" label={t('Number of lowercase chars must be greater or equals to')} fullWidth={true}
                             onSubmit={(name: string, value: string) => {
                               return handleSubmitField(name, value !== '' ? value : '0');
                             }}
                      />
                      <Field component={TextField} type="number" variant="standard" style={{ marginTop: 20 }}
                             name="password_policy_min_uppercase" label={t('Number of uppercase chars must be greater or equals to')} fullWidth={true}
                             onSubmit={(name: string, value: string) => {
                               return handleSubmitField(name, value !== '' ? value : '0');
                             }}
                      />
                    </Paper>
                  </div>
                </Form>
            )}
          </Formik>
      </Grid>
    </Grid>
  </div>;
};

export default AccessSettings;
