import React from 'react';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Grid from '@mui/material/Grid';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import * as Yup from 'yup';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { makeStyles } from '@mui/styles';
import Switch from '@mui/material/Switch';
import EEChip from '../common/entreprise_edition/EEChip';
import EnterpriseEditionButton from '../common/entreprise_edition/EnterpriseEditionButton';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation, QueryRenderer } from '../../../relay/environment';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import Loader from '../../../components/Loader';
import ColorPickerField from '../../../components/ColorPickerField';
import HiddenTypesField from './hidden_types/HiddenTypesField';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { isNotEmptyField } from '../../../utils/utils';
import SettingsMessages from './settings_messages/SettingsMessages';
import SettingsAnalytics from './settings_analytics/SettingsAnalytics';
import ItemBoolean from '../../../components/ItemBoolean';
import { availableLanguage } from '../../../components/AppIntlProvider';

const useStyles = makeStyles(() => ({
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
  button: {
    float: 'right',
    marginTop: -30,
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
      platform_whitemark
      platform_login_message
      platform_banner_text
      platform_banner_level
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
      enterprise_edition
      otp_mandatory
      ...SettingsMessages_settingsMessages
      analytics_google_analytics_v4
    }
    about {
      version
      dependencies {
        name
        version
      }
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
        platform_whitemark
        enterprise_edition
        platform_login_message
        platform_banner_text
        platform_banner_level
        analytics_google_analytics_v4
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
  platform_whitemark: Yup.string().nullable(),
  enterprise_edition: Yup.string().nullable(),
  platform_login_message: Yup.string().nullable(),
  platform_banner_text: Yup.string().nullable(),
  platform_banner_level: Yup.string().nullable(),
  analytics_google_analytics_v4: Yup.string().nullable(),
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
            const { settings, about } = props;
            const { id, editContext } = settings;
            const initialValues = R.pipe(
              R.pick([
                'platform_title',
                'platform_favicon',
                'platform_email',
                'platform_theme',
                'platform_language',
                'platform_login_message',
                'platform_banner_text',
                'platform_banner_level',
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
            const modules = settings.platform_modules;
            const { version, dependencies } = about;
            const isEnterpriseEdition = isNotEmptyField(
              settings.enterprise_edition,
            );
            return (
              <>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Configuration')}
                    </Typography>
                    <Paper
                      classes={{ root: classes.paper }}
                      variant="outlined"
                      style={{ marginTop: 15 }}
                    >
                      <Formik
                        onSubmit={() => {}}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t)}
                      >
                        {() => (
                          <Form>
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_title"
                              label={t('Platform title')}
                              fullWidth
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_title"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_favicon"
                              label={t('Platform favicon URL')}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_favicon"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_email"
                              label={t('Sender email address')}
                              fullWidth
                              style={{ marginTop: 20 }}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onSubmit={(name, value) => handleSubmitField(id, name, value)
                              }
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_email"
                                />
                              }
                            />
                            <Field
                              component={SelectField}
                              variant="standard"
                              name="platform_theme"
                              label={t('Theme')}
                              fullWidth
                              containerstyle={fieldSpacingContainerStyle}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onChange={(name, value) => handleSubmitField(id, name, value)
                              }
                              helpertext={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_theme"
                                />
                              }
                            >
                              <MenuItem value="dark">{t('Dark')}</MenuItem>
                              <MenuItem value="light">{t('Light')}</MenuItem>
                            </Field>
                            <Field
                              component={SelectField}
                              variant="standard"
                              name="platform_language"
                              label={t('Language')}
                              fullWidth
                              containerstyle={fieldSpacingContainerStyle}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onChange={(name, value) => handleSubmitField(id, name, value)
                              }
                              helpertext={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_language"
                                />
                              }
                            >
                              <MenuItem value="auto">
                                <em>{t('Automatic')}</em>
                              </MenuItem>
                              {
                                availableLanguage.map(({ value, label }) => <MenuItem key={value} value={value}>{label}</MenuItem>)
                              }
                            </Field>
                            <HiddenTypesField />
                          </Form>
                        )}
                      </Formik>
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography
                      variant="h4"
                      gutterBottom={true}
                      stye={{ float: 'left' }}
                    >
                      {t('OpenCTI platform')}
                    </Typography>
                    {!isEnterpriseEdition ? (
                      <EnterpriseEditionButton inLine />
                    ) : (
                      <Button
                        size="small"
                        variant="outlined"
                        color="primary"
                        onClick={() => handleSubmitField(id, 'enterprise_edition', '')
                        }
                        classes={{ root: classes.button }}
                      >
                        {t('Disable Enterprise Edition')}
                      </Button>
                    )}
                    <div className="clearfix" />
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Formik
                        onSubmit={() => {}}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t)}
                      >
                        {() => (
                          <Form>
                            <List style={{ marginTop: -20 }}>
                              <ListItem divider={true}>
                                <ListItemText primary={t('Version')} />
                                <ItemBoolean
                                  variant="inList"
                                  neutralLabel={version}
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText primary={t('Edition')} />
                                <ItemBoolean
                                  variant="inList"
                                  neutralLabel={
                                    isEnterpriseEdition
                                      ? t('Enterprise')
                                      : t('Community')
                                  }
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText
                                  primary={t('Architecture mode')}
                                />
                                <ItemBoolean
                                  variant="inList"
                                  neutralLabel={
                                    settings.platform_cluster.instances_number
                                    > 1
                                      ? t('Cluster')
                                      : t('Standalone')
                                  }
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText
                                  primary={t('Number of node(s)')}
                                />
                                <ItemBoolean
                                  variant="inList"
                                  neutralLabel={
                                    `${settings.platform_cluster.instances_number}`
                                  }
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <Field
                                  component={TextField}
                                  type="number"
                                  variant="standard"
                                  disabled={true}
                                  name="filigran_support_key"
                                  label={t('Filigran support key')}
                                  fullWidth={true}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText
                                  primary={
                                    <>
                                      {t('Remove Filigran logos')}
                                      <EEChip />
                                    </>
                                  }
                                ></ListItemText>
                                <Field
                                  component={Switch}
                                  variant="standard"
                                  name="platform_whitemark"
                                  disabled={!isEnterpriseEdition}
                                  checked={
                                    settings.platform_whitemark
                                    && isEnterpriseEdition
                                  }
                                  onChange={(event, value) => handleSubmitField(
                                    id,
                                    'platform_whitemark',
                                    value,
                                  )
                                  }
                                />
                              </ListItem>
                            </List>
                          </Form>
                        )}
                      </Formik>
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={8} style={{ marginTop: 30 }}>
                    <SettingsMessages settings={settings} />
                  </Grid>
                  <Grid item={true} xs={4} style={{ marginTop: 30 }}>
                    <SettingsAnalytics
                      settings={settings}
                      handleChangeFocus={handleChangeFocus}
                      handleSubmitField={handleSubmitField}
                      isEnterpriseEdition={isEnterpriseEdition}
                    />
                  </Grid>
                  <Grid item={true} xs={4} style={{ marginTop: 30 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Dark theme')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Formik
                        onSubmit={() => {}}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t)}
                      >
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
                  <Grid item={true} xs={4} style={{ marginTop: 30 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Light theme')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Formik
                        onSubmit={() => {}}
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
                  <Grid item={true} xs={4} style={{ marginTop: 30 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('Tools')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <List style={{ marginTop: -20 }}>
                        {modules.map((module) => {
                          const isEeModule = ['ACTIVITY_MANAGER', 'PLAYBOOK_MANAGER', 'FILE_INDEX_MANAGER'].includes(module.id);
                          let status = module.enable;
                          if (!isEnterpriseEdition && isEeModule) {
                            status = 'ee';
                          }
                          return (
                            <ListItem key={module.id} divider={true}>
                              <ListItemText primary={t(module.id)} />
                              <ItemBoolean
                                variant="inList"
                                label={
                                  module.enable ? t('Enabled') : t('Disabled')
                                }
                                status={status}
                              />
                            </ListItem>
                          );
                        })}
                        {dependencies.map((dep) => (
                          <ListItem key={dep.name} divider={true}>
                            <ListItemText primary={t(dep.name)} />
                            <ItemBoolean
                              variant="inList"
                              neutralLabel={dep.version}
                              status={null}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Grid>
                </Grid>
              </>
            );
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default Settings;
