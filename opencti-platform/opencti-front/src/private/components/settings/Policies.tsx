import React, { FunctionComponent } from 'react';
import {
  graphql,
  useFragment,
  useMutation,
  useLazyLoadQuery,
} from 'react-relay';
import { Form, Formik, Field } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { makeStyles } from '@mui/styles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import MenuItem from '@mui/material/MenuItem';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { VpnKeyOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import Chip from '@mui/material/Chip';
import AccessesMenu from './AccessesMenu';
import ObjectOrganizationField from '../common/form/ObjectOrganizationField';
import { useFormatter } from '../../../components/i18n';
import { Option } from '../common/form/ReferenceField';
import SwitchField from '../../../components/SwitchField';
import TextField from '../../../components/TextField';
import { Policies$key } from './__generated__/Policies.graphql';
import MarkdownField from '../../../components/MarkdownField';
import { PoliciesQuery } from './__generated__/PoliciesQuery.graphql';
import SelectField from '../../../components/SelectField';

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
    platform_login_message
    platform_consent_message
    platform_consent_confirm_text
    platform_banner_level
    platform_banner_text
    password_policy_min_length
    password_policy_max_length
    password_policy_min_symbols
    password_policy_min_numbers
    password_policy_min_words
    password_policy_min_lowercase
    password_policy_min_uppercase
    platform_providers {
      name
      strategy
    }
    platform_organization {
      id
      name
    }
    otp_mandatory
  }
`;

const policiesQuery = graphql`
  query PoliciesQuery {
    settings {
      ...Policies
    }
  }
`;

export const policiesFieldPatch = graphql`
  mutation PoliciesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        ...Policies
      }
    }
  }
`;

const policiesValidation = () => Yup.object().shape({
  platform_organization: Yup.object().nullable(),
  otp_mandatory: Yup.boolean(),
  password_policy_min_length: Yup.number(),
  password_policy_max_length: Yup.number(),
  password_policy_min_symbols: Yup.number(),
  password_policy_min_numbers: Yup.number(),
  password_policy_min_words: Yup.number(),
  password_policy_min_lowercase: Yup.number(),
  password_policy_min_uppercase: Yup.number(),
  platform_login_message: Yup.string().nullable(),
  platform_consent_message: Yup.string().nullable(),
  platform_consent_confirm_text: Yup.string().nullable(),
  platform_banner_level: Yup.string().nullable(),
  platform_banner_text: Yup.string().nullable(),
});

const Policies: FunctionComponent = () => {
  const data = useLazyLoadQuery<PoliciesQuery>(policiesQuery, {});
  const settings = useFragment<Policies$key>(PoliciesFragment, data.settings);
  const [commitField] = useMutation(policiesFieldPatch);
  const classes = useStyles();
  const { t } = useFormatter();
  const handleSubmitField = (name: string, value: unknown) => {
    policiesValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitField({
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
    platform_login_message: settings.platform_login_message,
    platform_consent_message: settings.platform_consent_message,
    platform_consent_confirm_text: settings.platform_consent_confirm_text,
    password_policy_min_length: settings.password_policy_min_length,
    password_policy_max_length: settings.password_policy_max_length,
    password_policy_min_symbols: settings.password_policy_min_symbols,
    password_policy_min_numbers: settings.password_policy_min_numbers,
    password_policy_min_words: settings.password_policy_min_words,
    password_policy_min_lowercase: settings.password_policy_min_lowercase,
    password_policy_min_uppercase: settings.password_policy_min_uppercase,
    platform_banner_level: settings.platform_banner_level,
    platform_banner_text: settings.platform_banner_text,
    otp_mandatory: settings.otp_mandatory,
  };
  const authProviders = settings.platform_providers;
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={12}>
          <Formik
            onSubmit={() => {}}
            initialValues={initialValues}
            enableReinitialize={true}
            validationSchema={policiesValidation()}
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
                      {t('Authentication strategies')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <List style={{ marginTop: -20 }}>
                        {authProviders.map((provider) => (
                          <ListItem key={provider.strategy} divider={true}>
                            <ListItemIcon>
                              <VpnKeyOutlined color="primary" />
                            </ListItemIcon>
                            <ListItemText
                              primary={provider.name}
                              secondary={provider.strategy}
                            />
                            <Chip label={t('Enabled')} color="success" />
                          </ListItem>
                        ))}
                      </List>
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="otp_mandatory"
                        label={t('Enforce two-factor authentication')}
                        containerstyle={{ marginTop: 20 }}
                        onChange={(name: string, value: string) => handleSubmitField(name, value)
                        }
                        tooltip={t(
                          'When enforcing 2FA authentication, all users will be asked to enable 2FA to be able to login in the platform.',
                        )}
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
                  <Grid item={true} xs={6} style={{ marginTop: 30 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Login messages')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Field
                        component={MarkdownField}
                        name="platform_login_message"
                        label={t('Platform login message')}
                        fullWidth
                        multiline={true}
                        rows="3"
                        onSubmit={handleSubmitField}
                        variant="standard"
                      />
                      <Field
                        component={MarkdownField}
                        name="platform_consent_message"
                        label={t('Platform consent message')}
                        fullWidth
                        style={{ marginTop: 20 }}
                        onSubmit={handleSubmitField}
                        variant="standard"
                      />
                      <Field
                        component={MarkdownField}
                        name="platform_consent_confirm_text"
                        label={t('Platform consent confirm text')}
                        fullWidth
                        style={{ marginTop: 20 }}
                        height={38}
                        onSubmit={handleSubmitField}
                        variant="standard"
                      />
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography
                      variant="h4"
                      gutterBottom={true}
                      style={{ marginTop: '30px' }}
                    >
                      {t('Platform Banner Configuration')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Field
                        component={SelectField}
                        variant="standard"
                        name="platform_banner_level"
                        label={t('Platform Banner Level')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 5, width: '100%' }}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(name, value);
                        }}
                      >
                        <MenuItem value="">&nbsp;</MenuItem>
                        <MenuItem value="GREEN">{t('GREEN')}</MenuItem>
                        <MenuItem value="RED">{t('RED')}</MenuItem>
                        <MenuItem value="YELLOW">{t('YELLOW')}</MenuItem>
                      </Field>
                      <Field
                        component={MarkdownField}
                        name="platform_banner_text"
                        label={t('Platform Banner Text')}
                        fullWidth={true}
                        height={38}
                        style={{ marginTop: 20 }}
                        onSubmit={handleSubmitField}
                        variant="standard"
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
