import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { makeStyles } from '@mui/styles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import AccessesMenu from './AccessesMenu';
import ObjectOrganizationField from '../common/form/ObjectOrganizationField';
import { useFormatter } from '../../../components/i18n';
import { Option } from '../common/form/ReferenceField';
import SwitchField from '../../../components/SwitchField';
import TextField from '../../../components/TextField';
import useAuth from '../../../utils/hooks/useAuth';
import { Policies$key } from './__generated__/Policies.graphql';

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

const PoliciesFragment = graphql`
  fragment Policies on Settings {
    id
    password_policy_min_length
    password_policy_max_length
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

export const PoliciesFieldPatch = graphql`
  mutation PoliciesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        ...Policies
      }
    }
  }
`;

const settingsValidation = () => Yup.object().shape({
  platform_organization: Yup.object().nullable(),
  otp_mandatory: Yup.boolean(),
  password_policy_min_length: Yup.number(),
  password_policy_max_length: Yup.number(),
  password_policy_min_symbols: Yup.number(),
  password_policy_min_numbers: Yup.number(),
  password_policy_min_words: Yup.number(),
  password_policy_min_lowercase: Yup.number(),
  password_policy_min_uppercase: Yup.number(),
});

const Policies: FunctionComponent = () => {
  const { settings: rawSettings } = useAuth();
  const settings = useFragment<Policies$key>(PoliciesFragment, rawSettings);
  const [commit] = useMutation(PoliciesFieldPatch);
  const classes = useStyles();
  const { t } = useFormatter();
  const handleSubmitField = (name: string, value: unknown) => {
    settingsValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commit({
          variables: {
            id: settings.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };
  const initialValues = {
    platform_organization: settings.platform_organization
      ? {
        label: settings.platform_organization?.name,
        value: settings.platform_organization?.id,
      }
      : '',
    password_policy_min_length: settings.password_policy_min_length,
    password_policy_max_length: settings.password_policy_max_length,
    password_policy_min_symbols: settings.password_policy_min_symbols,
    password_policy_min_numbers: settings.password_policy_min_numbers,
    password_policy_min_words: settings.password_policy_min_words,
    password_policy_min_lowercase: settings.password_policy_min_lowercase,
    password_policy_min_uppercase: settings.password_policy_min_uppercase,
    otp_mandatory: settings.otp_mandatory,
  };
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={12}>
          <Formik
            onSubmit={() => {}}
            initialValues={initialValues}
            validationSchema={settingsValidation()}
          >
            {() => (
              <Form>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Platform main organization')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Alert severity="warning">
                        {t(
                          'When you set a platform organization, all the pieces of knowledge which are not shared with any organization will be accessible only for users part of the platform one.',
                        )}
                      </Alert>
                      <ObjectOrganizationField
                        name="platform_organization"
                        label={'Platform organization'}
                        onChange={(name: string, value: Option) => handleSubmitField(name, value.value)
                        }
                        style={{ width: '100%', marginTop: 20 }}
                        multiple={false}
                        outlined={false}
                      />
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Two-factor authentication')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Alert severity="info">
                        {t(
                          'When enforcing 2FA, all users will be asked to enable 2FA to be able to login in the platform.',
                        )}
                      </Alert>
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="otp_mandatory"
                        label={t('Enforce two-factor authentication')}
                        containerstyle={{ marginTop: 20 }}
                        onChange={(name: string, value: string) => handleSubmitField(name, value)
                        }
                      />
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={6} style={{ marginTop: 30 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Local password policies')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        name="password_policy_min_length"
                        label={t(
                          'Number of chars must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_max_length"
                        label={`${t(
                          'Number of chars must be lower or equals to',
                        )} (${t('0 equals no maximum')})`}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_symbols"
                        label={t(
                          'Number of symbols must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_numbers"
                        label={t(
                          'Number of digits must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_words"
                        label={t(
                          'Number of words (split on hyphen, space) must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_lowercase"
                        label={t(
                          'Number of lowercase chars must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_uppercase"
                        label={t(
                          'Number of uppercase chars must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                    </Paper>
                  </Grid>
                </Grid>
              </Form>
            )}
          </Formik>
        </Grid>
      </Grid>
    </div>
  );
};

export default Policies;
