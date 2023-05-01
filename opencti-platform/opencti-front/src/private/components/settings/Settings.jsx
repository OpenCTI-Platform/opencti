import React from 'react';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import * as Yup from 'yup';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Chip from '@mui/material/Chip';
import { deepPurple } from '@mui/material/colors';
import { makeStyles } from '@mui/styles';
import { VpnKeyOutlined } from '@mui/icons-material';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation, QueryRenderer } from '../../../relay/environment';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import Loader from '../../../components/Loader';
import MarkDownField from '../../../components/MarkDownField';
import ColorPickerField from '../../../components/ColorPickerField';
import HiddenTypesList from './entity_settings/HiddenTypesList';
import { fieldSpacingContainerStyle } from '../../../utils/field';

const useStyles = makeStyles((theme) => ({
  container: {
    margin: '0 0 60px 0',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
  purple: {
    color: theme.palette.getContrastText(deepPurple[500]),
    backgroundColor: deepPurple[500],
  },
  button: {
    float: 'left',
    margin: '20px 0 20px 0',
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
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

const settingsQuery = graphql`
  query SettingsQuery {
    settings {
      id
      platform_title
      platform_favicon
      platform_email
      platform_theme
      platform_language
      platform_login_message
      platform_consent_message
      platform_consent_confirm_text
      platform_theme_dark_background
      platform_theme_dark_paper
      platform_theme_dark_nav
      platform_theme_dark_primary
      platform_theme_dark_secondary
      platform_theme_dark_accent
      platform_theme_dark_logo
      platform_theme_dark_logo_collapsed
      platform_theme_dark_logo_login
      platform_theme_light_background
      platform_theme_light_paper
      platform_theme_light_nav
      platform_theme_light_primary
      platform_theme_light_secondary
      platform_theme_light_accent
      platform_theme_light_logo
      platform_theme_light_logo_collapsed
      platform_theme_light_logo_login
      platform_organization {
        id
        name
      }
      platform_providers {
        name
        strategy
      }
      platform_modules {
        id
        enable
        running
      }
      platform_cluster {
        instances_number
      }
      editContext {
        name
        focusOn
      }
      otp_mandatory
    }
  }
`;

export const settingsMutationFieldPatch = graphql`
  mutation SettingsFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        platform_title
        platform_favicon
        platform_email
        platform_theme
        platform_theme_dark_background
        platform_theme_dark_paper
        platform_theme_dark_nav
        platform_theme_dark_primary
        platform_theme_dark_secondary
        platform_theme_dark_accent
        platform_theme_dark_logo
        platform_theme_dark_logo_collapsed
        platform_theme_dark_logo_login
        platform_theme_light_background
        platform_theme_light_paper
        platform_theme_light_nav
        platform_theme_light_primary
        platform_theme_light_secondary
        platform_theme_light_accent
        platform_theme_light_logo
        platform_theme_light_logo_collapsed
        platform_theme_light_logo_login
        platform_language
        platform_login_message
        platform_consent_message
        platform_consent_confirm_text
      }
    }
  }
`;

const settingsFocus = graphql`
  mutation SettingsFocusMutation($id: ID!, $input: EditContext!) {
    settingsEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const settingsAboutQuery = graphql`
  query SettingsAboutQuery {
    about {
      version
      dependencies {
        name
        version
      }
    }
  }
`;

const settingsValidation = (t) => Yup.object().shape({
  platform_title: Yup.string().required(t('This field is required')),
  platform_favicon: Yup.string().nullable(),
  platform_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  platform_theme: Yup.string().nullable(),
  platform_theme_dark_background: Yup.string().nullable(),
  platform_theme_dark_paper: Yup.string().nullable(),
  platform_theme_dark_nav: Yup.string().nullable(),
  platform_theme_dark_primary: Yup.string().nullable(),
  platform_theme_dark_secondary: Yup.string().nullable(),
  platform_theme_dark_accent: Yup.string().nullable(),
  platform_theme_dark_logo: Yup.string().nullable(),
  platform_theme_dark_logo_collapsed: Yup.string().nullable(),
  platform_theme_dark_logo_login: Yup.string().nullable(),
  platform_theme_light_background: Yup.string().nullable(),
  platform_theme_light_paper: Yup.string().nullable(),
  platform_theme_light_nav: Yup.string().nullable(),
  platform_theme_light_primary: Yup.string().nullable(),
  platform_theme_light_secondary: Yup.string().nullable(),
  platform_theme_light_accent: Yup.string().nullable(),
  platform_theme_light_logo: Yup.string().nullable(),
  platform_theme_light_logo_collapsed: Yup.string().nullable(),
  platform_theme_light_logo_login: Yup.string().nullable(),
  platform_language: Yup.string().nullable(),
  platform_login_message: Yup.string().nullable(),
  platform_consent_message: Yup.string().nullable(),
  platform_consent_confirm_text: Yup.string().nullable(),
});

const Settings = () => {
  const classes = useStyles();
  const { t } = useFormatter();

  const handleChangeFocus = (id, name) => {
    commitMutation({
      mutation: settingsFocus,
      variables: {
        id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (id, name, value) => {
    let finalValue = value;
    if (
      [
        'platform_theme_dark_background',
        'platform_theme_dark_paper',
        'platform_theme_dark_nav',
        'platform_theme_dark_primary',
        'platform_theme_dark_secondary',
        'platform_theme_dark_accent',
        'platform_theme_light_background',
        'platform_theme_light_paper',
        'platform_theme_light_nav',
        'platform_theme_light_primary',
        'platform_theme_light_secondary',
        'platform_theme_light_accent',
      ].includes(name)
      && finalValue.length > 0
    ) {
      if (!finalValue.startsWith('#')) {
        finalValue = `#${finalValue}`;
      }
      finalValue = finalValue.substring(0, 7);
      if (finalValue.length < 7) {
        finalValue = '#000000';
      }
    }
    settingsValidation(t)
      .validateAt(name, { [name]: finalValue })
      .then(() => {
        commitMutation({
          mutation: settingsMutationFieldPatch,
          variables: { id, input: { key: name, value: finalValue || '' } },
        });
      })
      .catch(() => false);
  };

  return (
    <div className={classes.container}>
      <QueryRenderer
        query={settingsQuery}
        render={({ props }) => {
          if (props && props.settings) {
            const { settings } = props;
            const { id, editContext } = settings;
            const initialValues = R.pipe(
              R.pick([
                'platform_title',
                'platform_favicon',
                'platform_email',
                'platform_theme',
                'platform_language',
                'platform_login_message',
                'platform_consent_message',
                'platform_consent_confirm_text',
                'platform_theme_dark_background',
                'platform_theme_dark_paper',
                'platform_theme_dark_nav',
                'platform_theme_dark_primary',
                'platform_theme_dark_secondary',
                'platform_theme_dark_accent',
                'platform_theme_dark_logo',
                'platform_theme_dark_logo_collapsed',
                'platform_theme_dark_logo_login',
                'platform_theme_light_background',
                'platform_theme_light_paper',
                'platform_theme_light_nav',
                'platform_theme_light_primary',
                'platform_theme_light_secondary',
                'platform_theme_light_accent',
                'platform_theme_light_logo',
                'platform_theme_light_logo_collapsed',
                'platform_theme_light_logo_login',
                'platform_map_tile_server_dark',
                'platform_map_tile_server_light',
              ]),
            )(settings);
            const authProviders = settings.platform_providers;
            const modules = settings.platform_modules;
            return (
              <div>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Configuration')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Formik onSubmit={() => {}} enableReinitialize={true} initialValues={initialValues}
                        validationSchema={settingsValidation(t)}>
                        {() => (
                          <Form>
                            <Field component={TextField}
                              variant="standard"
                              name="platform_title"
                              label={t('Platform title')}
                              fullWidth
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)}
                              helperText={<SubscriptionFocus context={editContext} fieldName="platform_title"/>}
                            />
                            <Field component={TextField}
                              variant="standard"
                              name="platform_favicon"
                              label={t('Platform favicon URL')}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)}
                              helperText={<SubscriptionFocus context={editContext} fieldName="platform_favicon"/>}
                            />
                            <Field component={TextField}
                              variant="standard"
                              name="platform_email"
                              label={t('Sender email address')}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)}
                              helperText={<SubscriptionFocus context={editContext} fieldName="platform_email"/>}
                            />
                            <Field component={SelectField}
                              variant="standard"
                              name="platform_theme"
                              label={t('Theme')}
                              fullWidth
                              containerstyle={fieldSpacingContainerStyle}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onChange={(name, value) => handleSubmitField(id, name, value)}
                              helpertext={<SubscriptionFocus context={editContext} fieldName="platform_theme"/>}>
                              <MenuItem value="dark">{t('Dark')}</MenuItem>
                              <MenuItem value="light">{t('Light')}</MenuItem>
                            </Field>
                            <Field component={SelectField}
                              variant="standard"
                              name="platform_language"
                              label={t('Language')}
                              fullWidth
                              containerstyle={fieldSpacingContainerStyle}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onChange={(name, value) => handleSubmitField(id, name, value)}
                              helpertext={<SubscriptionFocus context={editContext} fieldName="platform_language"/>}>
                              <MenuItem value="auto">
                                <em>{t('Automatic')}</em>
                              </MenuItem>
                              <MenuItem value="en-us">English</MenuItem>
                              <MenuItem value="fr-fr">Français</MenuItem>
                              <MenuItem value="es-es">Español</MenuItem>
                              <MenuItem value="ja-jp">日本語</MenuItem>
                              <MenuItem value="zh-cn">简化字</MenuItem>
                            </Field>
                            <HiddenTypesList />
                          </Form>
                        )}
                      </Formik>
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
                      <Formik onSubmit={() => {}} enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t)}>
                        {() => (
                          <Form>
                            <Typography variant="h1" gutterBottom={true} style={{ marginTop: '20px' }}>
                            {t('Platform Message Configuration')}
                            </Typography>
                            <Typography variant="h4" gutterBottom={true} style={{ marginTop: '20px' }}>
                              {t('Platform Login Message')}
                            </Typography>
                            <Field
                              component={MarkDownField}
                              name="platform_login_message"
                              label={t('Platform login message')}
                              fullWidth
                              multiline={true}
                              rows="3"
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)}
                              variant="standard"
                              helperText={<SubscriptionFocus context={editContext} fieldName="platform_login_message"/>}
                            />
                            <Typography variant="h4" gutterBottom={true} style={{ marginTop: '20px' }}>
                              {t('Platform Consent Message')}
                            </Typography>
                            <Field
                              component={MarkDownField}
                              name="platform_consent_message"
                              label={t('Platform Consent Message - requires acceptance to enable login form when set')}
                              fullWidth
                              multiline={true}
                              rows="3"
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_consent_message"
                                />
                              }
                            />
                            <Typography variant="h4" gutterBottom={true} style={{ marginTop: '20px' }}>
                              {t('Platform Consent Confirm Text')}
                            </Typography>
                            <Field
                              component={MarkDownField}
                              name="platform_consent_confirm_text"
                              label={`${t('Platform Consent Confirm Text - confirm label next to confirm checkbox')
                              }. ${t('Default')}: ${
                                t('I have read and comply with the above statement')}`
                                    }
                              fullWidth
                              multiline={true}
                              rows="3"
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_consent_confirm_text"
                                />
                              }
                            />
                          </Form>
                        )}
                      </Formik>
                    </Paper>
                  </Grid>
                </Grid>
                <Grid container={true} spacing={3} style={{ marginTop: 25 }}>
                  <Grid item={true} xs={4}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Dark theme')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Formik onSubmit={() => {}}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t)}>
                        {() => (
                          <Form>
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_dark_background"
                              label={t('Background color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_background"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_dark_paper"
                              label={t('Paper color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_paper"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_dark_nav"
                              label={t('Navigation color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_nav"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_dark_primary"
                              label={t('Primary color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_primary"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_dark_secondary"
                              label={t('Secondary color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_secondary"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_dark_accent"
                              label={t('Accent color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_accent"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_theme_dark_logo"
                              label={t('Logo URL')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_logo"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_theme_dark_logo_collapsed"
                              label={t('Logo URL (collapsed)')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_logo_collapsed"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_theme_dark_logo_login"
                              label={t('Logo URL (login)')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_dark_logo_login"
                                />
                              }
                            />
                          </Form>
                        )}
                      </Formik>
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Light theme')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Formik
                        onSubmit={() => {
                        }}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t)}
                      >
                        {() => (
                          <Form>
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_light_background"
                              label={t('Background color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_background"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_light_paper"
                              label={t('Paper color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_paper"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_light_nav"
                              label={t('Navigation color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_nav"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_light_primary"
                              label={t('Primary color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_primary"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_light_secondary"
                              label={t('Secondary color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_secondary"
                                />
                              }
                            />
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_light_accent"
                              label={t('Accent color')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              variant="standard"
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_accent"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_theme_light_logo"
                              label={t('Logo URL')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_logo"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_theme_light_logo_collapsed"
                              label={t('Logo URL (collapsed)')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_logo_collapsed"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_theme_light_logo_login"
                              label={t('Logo URL (login)')}
                              placeholder={t('Default')}
                              InputLabelProps={{
                                shrink: true,
                              }}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme_light_logo_login"
                                />
                              }
                            />
                          </Form>
                        )}
                      </Formik>
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Tools')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <QueryRenderer
                        query={settingsAboutQuery}
                        render={({ props: aboutProps }) => {
                          if (aboutProps) {
                            const { version, dependencies } = aboutProps.about;
                            const clusterInfo = settings.platform_cluster.instances_number > 1
                              ? `Cluster of ${settings.platform_cluster.instances_number} nodes`
                              : 'Single node';
                            return (
                              <List style={{ marginTop: -20 }}>
                                <ListItem divider={true}>
                                  <ListItemText
                                    primary={`OpenCTI (${clusterInfo})`}
                                  />
                                  <Chip label={version} color="primary" />
                                </ListItem>
                                <List component="div" disablePadding>
                                  {modules.map((module) => (
                                    <ListItem
                                      key={module.id}
                                      divider={true}
                                      className={classes.nested}
                                    >
                                      <ListItemText primary={t(module.id)} />
                                      <Chip
                                        label={
                                          module.enable
                                            ? t('Enabled')
                                            : t('Disabled')
                                        }
                                        color={
                                          module.enable ? 'success' : 'error'
                                        }
                                      />
                                    </ListItem>
                                  ))}
                                </List>
                                {dependencies.map((dep) => (
                                  <ListItem key={dep.name} divider={true}>
                                    <ListItemText primary={t(dep.name)} />
                                    <Chip label={dep.version} color="primary" />
                                  </ListItem>
                                ))}
                              </List>
                            );
                          }
                          return <Loader variant="inElement" />;
                        }}
                      />
                    </Paper>
                  </Grid>
                </Grid>
              </div>
            );
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default Settings;
