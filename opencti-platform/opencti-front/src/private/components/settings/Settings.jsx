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
import { makeStyles, useTheme } from '@mui/styles';
import Switch from '@mui/material/Switch';
import DangerZoneBlock from '../common/dangerZone/DangerZoneBlock';
import EEChip from '../common/entreprise_edition/EEChip';
import EnterpriseEditionButton from '../common/entreprise_edition/EnterpriseEditionButton';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation, QueryRenderer } from '../../../relay/environment';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/fields/SelectField';
import Loader from '../../../components/Loader';
import ColorPickerField from '../../../components/ColorPickerField';
import HiddenTypesField from './hidden_types/HiddenTypesField';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { isNotEmptyField } from '../../../utils/utils';
import SettingsMessages from './settings_messages/SettingsMessages';
import SettingsAnalytics from './settings_analytics/SettingsAnalytics';
import ItemBoolean from '../../../components/ItemBoolean';
import { availableLanguage } from '../../../components/AppIntlProvider';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useSensitiveModifications from '../../../utils/hooks/useSensitiveModifications';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: '0 0 60px 0',
  },
  paper: {
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 4,
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
      platform_ai_enabled
      platform_ai_type
      platform_ai_model
      platform_ai_has_token
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
  const theme = useTheme();

  const { isSensitiveModificationEnabled, isAllowed } = useSensitiveModifications();

  const { t_i18n } = useFormatter();
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
    settingsValidation(t_i18n)
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
                <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Parameters'), current: true }]} />
                <Grid container={true} spacing={3}>
                  <Grid item xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Configuration')}
                    </Typography>
                    <Paper
                      classes={{ root: classes.paper }}
                      variant="outlined"
                      className={'paper-for-grid'}
                    >
                      <Formik
                        onSubmit={() => {
                        }}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t_i18n)}
                      >
                        {() => (
                          <Form>
                            <Field
                              component={TextField}
                              variant="standard"
                              name="platform_title"
                              label={t_i18n('Platform title')}
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
                              label={t_i18n('Platform favicon URL')}
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
                              label={t_i18n('Sender email address')}
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
                              label={t_i18n('Theme')}
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
                              <MenuItem value="dark">{t_i18n('Dark')}</MenuItem>
                              <MenuItem value="light">{t_i18n('Light')}</MenuItem>
                            </Field>
                            <Field
                              component={SelectField}
                              variant="standard"
                              name="platform_language"
                              label={t_i18n('Language')}
                              fullWidth
                              containerstyle={fieldSpacingContainerStyle}
                              onFocus={(name) => handleChangeFocus(id, name)}
                              onChange={(name, value) => handleSubmitField(id, name, value)}
                              helpertext={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_language"
                                />
                              }
                            >
                              <MenuItem value="auto">
                                <em>{t_i18n('Automatic')}</em>
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
                  <Grid item xs={6}>
                    <Typography variant="h4" gutterBottom={true} stye={{ float: 'left' }}>
                      {t_i18n('OpenCTI platform')}
                    </Typography>
                    <div style={{ float: 'right', marginTop: isSensitiveModificationEnabled ? theme.spacing(-5) : theme.spacing(-4.5), position: 'relative' }}>
                      {!isEnterpriseEdition ? (
                        <EnterpriseEditionButton disabled={!isAllowed} inLine />
                      ) : (
                        <DangerZoneBlock
                          sx={{
                            root: { border: 'none', padding: 0, margin: 0 },
                            title: { position: 'absolute', zIndex: 2, left: 4, top: 9, fontSize: 8 },
                          }}
                        >
                          {({ disabled }) => (
                            <Button
                              size="small"
                              variant="outlined"
                              color={isSensitiveModificationEnabled ? 'dangerZone' : 'primary'}
                              onClick={() => handleSubmitField(id, 'enterprise_edition', '')}
                              disabled={disabled}
                            >
                              {t_i18n('Disable Enterprise Edition')}
                            </Button>
                          )}
                        </DangerZoneBlock>
                      )}
                    </div>
                    <Paper
                      classes={{ root: classes.paper }}
                      className={'paper-for-grid'}
                      variant="outlined"
                    >
                      <Formik
                        onSubmit={() => {
                        }}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t_i18n)}
                      >
                        {() => (
                          <Form>
                            <List style={{ marginTop: -20 }}>
                              <ListItem divider={true}>
                                <ListItemText primary={t_i18n('Version')} />
                                <ItemBoolean
                                  variant="large"
                                  neutralLabel={version}
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText primary={t_i18n('Edition')} />
                                <ItemBoolean
                                  variant="large"
                                  neutralLabel={
                                    isEnterpriseEdition
                                      ? t_i18n('Enterprise')
                                      : t_i18n('Community')
                                  }
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText
                                  primary={t_i18n('Architecture mode')}
                                />
                                <ItemBoolean
                                  variant="large"
                                  neutralLabel={
                                    settings.platform_cluster.instances_number
                                    > 1
                                      ? t_i18n('Cluster')
                                      : t_i18n('Standalone')
                                  }
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText
                                  primary={t_i18n('Number of node(s)')}
                                />
                                <ItemBoolean
                                  variant="large"
                                  neutralLabel={
                                    `${settings.platform_cluster.instances_number}`
                                  }
                                  status={null}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText
                                  primary={t_i18n('AI Powered')}
                                />
                                <ItemBoolean
                                  variant="large"
                                  label={
                                    // eslint-disable-next-line no-nested-ternary
                                    !settings.platform_ai_enabled ? t_i18n('Disabled') : settings.platform_ai_has_token
                                      ? settings.platform_ai_type : `${settings.platform_ai_type} - ${t_i18n('Missing token')}`}
                                  status={settings.platform_ai_enabled && settings.platform_ai_has_token}
                                  tooltip={settings.platform_ai_has_token ? `${settings.platform_ai_type} - ${settings.platform_ai_model}` : t_i18n('The token is missing in your platform configuration, please ask your Filigran representative to provide you with it or with on-premise deployment instructions. Your can open a support ticket to do so.')}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <Field
                                  component={TextField}
                                  type="number"
                                  variant="standard"
                                  disabled={true}
                                  name="filigran_support_key"
                                  label={t_i18n('Filigran support key')}
                                  fullWidth={true}
                                />
                              </ListItem>
                              <ListItem divider={true}>
                                <ListItemText
                                  primary={
                                    <>
                                      {t_i18n('Remove Filigran logos')}
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
                  <Grid item xs={8}>
                    <SettingsMessages settings={settings} />
                  </Grid>
                  <Grid item xs={4}>
                    <SettingsAnalytics
                      settings={settings}
                      handleChangeFocus={handleChangeFocus}
                      handleSubmitField={handleSubmitField}
                      isEnterpriseEdition={isEnterpriseEdition}
                    />
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Dark theme')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
                      <Formik
                        onSubmit={() => {
                        }}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t_i18n)}
                      >
                        {() => (
                          <Form>
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_dark_background"
                              label={t_i18n('Background color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Paper color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Navigation color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Primary color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Secondary color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Accent color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Logo URL')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Logo URL (collapsed)')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Logo URL (login)')}
                              placeholder={t_i18n('Default')}
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
                  <Grid item xs={4}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Light theme')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
                      <Formik
                        onSubmit={() => {
                        }}
                        enableReinitialize={true}
                        initialValues={initialValues}
                        validationSchema={settingsValidation(t_i18n)}
                      >
                        {() => (
                          <Form>
                            <Field
                              component={ColorPickerField}
                              name="platform_theme_light_background"
                              label={t_i18n('Background color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Paper color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Navigation color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Primary color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Secondary color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Accent color')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Logo URL')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Logo URL (collapsed)')}
                              placeholder={t_i18n('Default')}
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
                              label={t_i18n('Logo URL (login)')}
                              placeholder={t_i18n('Default')}
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
                  <Grid item xs={4}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Tools')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
                      <List style={{ marginTop: -20 }}>
                        {modules.map((module) => {
                          const isEeModule = ['ACTIVITY_MANAGER', 'PLAYBOOK_MANAGER', 'FILE_INDEX_MANAGER'].includes(module.id);
                          let status = module.enable;
                          if (!isEnterpriseEdition && isEeModule) {
                            status = 'ee';
                          }
                          return (
                            <ListItem key={module.id} divider={true}>
                              <ListItemText primary={t_i18n(module.id)} />
                              <ItemBoolean
                                variant="large"
                                label={module.enable ? t_i18n('Enabled') : t_i18n('Disabled')}
                                status={status}
                              />
                            </ListItem>
                          );
                        })}
                        {dependencies.map((dep) => (
                          <ListItem key={dep.name} divider={true}>
                            <ListItemText primary={t_i18n(dep.name)} />
                            <ItemBoolean
                              variant="large"
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
