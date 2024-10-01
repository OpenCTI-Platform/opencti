import React, { useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
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
import { useTheme } from '@mui/styles';
import Switch from '@mui/material/Switch';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Alert from '@mui/material/Alert';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DangerZoneBlock from '../common/danger_zone/DangerZoneBlock';
import EEChip from '../common/entreprise_edition/EEChip';
import EnterpriseEditionButton from '../common/entreprise_edition/EnterpriseEditionButton';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation, defaultCommitMutation } from '../../../relay/environment';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/fields/SelectField';
import HiddenTypesField from './hidden_types/HiddenTypesField';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import SettingsMessages from './settings_messages/SettingsMessages';
import SettingsAnalytics from './settings_analytics/SettingsAnalytics';
import ItemBoolean from '../../../components/ItemBoolean';
import { availableLanguage } from '../../../components/AppIntlProvider';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useSensitiveModifications from '../../../utils/hooks/useSensitiveModifications';
import Transition from '../../../components/Transition';
import ItemCopy from '../../../components/ItemCopy';
import Loader from '../../../components/Loader';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { SettingsQuery } from './__generated__/SettingsQuery.graphql';
import type { Theme } from '../../../components/Theme';
import Themes, { refetchableThemesQuery } from './themes/Themes';
import { Themes_themes$key } from './themes/__generated__/Themes_themes.graphql';
import { deserializeThemeManifest } from './themes/ThemeType';
import useApiMutation from '../../../utils/hooks/useApiMutation';

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
      platform_enterprise_edition {
        license_enterprise
        license_by_configuration
        license_valid_cert
        license_validated
        license_expiration_prevention
        license_customer
        license_expiration_date
        license_start_date
        license_platform_match
        license_expired
        license_type
        license_creator
        license_global
      }
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
    ...Themes_themes
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
        platform_language
        platform_whitemark
        platform_enterprise_edition {
          license_enterprise
          license_validated
          license_customer
          license_valid_cert
          license_expiration_prevention
          license_platform_match
          license_expiration_date
          license_start_date
          license_expired
          license_type
          license_creator
          license_global
        }
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

const settingsValidation = (t: (s: string) => string) => Yup.object().shape({
  platform_title: Yup.string().required(t('This field is required')),
  platform_favicon: Yup.string().nullable(),
  platform_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  platform_theme: Yup.string().nullable(),
  platform_language: Yup.string().nullable(),
  platform_whitemark: Yup.string().nullable(),
  enterprise_license: Yup.string().nullable(),
  platform_login_message: Yup.string().nullable(),
  platform_banner_text: Yup.string().nullable(),
  platform_banner_level: Yup.string().nullable(),
  analytics_google_analytics_v4: Yup.string().nullable(),
});

const Settings = (queryRef: PreloadedQuery<SettingsQuery>) => {
  const theme = useTheme<Theme>();

  const { isAllowed } = useSensitiveModifications('ce_ee_toggle');
  const [openEEChanges, setOpenEEChanges] = useState(false);
  const [commit] = useApiMutation(settingsMutationFieldPatch);

  const data = usePreloadedQuery<SettingsQuery>(settingsQuery, queryRef);
  const [{ themes }, refetch] = useRefetchableFragment<
  SettingsQuery,
  Themes_themes$key
  >(
    refetchableThemesQuery,
    data,
  );

  const { t_i18n, fldt } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Parameters | Settings'));
  const handleChangeFocus = (id: string, name: string) => {
    commitMutation({
      ...defaultCommitMutation,
      mutation: settingsFocus,
      variables: {
        id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const handleSubmitField = (id: string, name: string, value: string | null) => {
    const finalValue = value ?? '';
    settingsValidation(t_i18n)
      .validateAt(name, { [name]: finalValue })
      .then(() => {
        commit({
          variables: { id, input: { key: name, value: finalValue } },
        });
      })
      .catch(() => false);
  };
  const handleRefetch = () => refetch(
    {},
    { fetchPolicy: 'network-only' },
  );

  const { settings, about } = data;

  if (!settings || !about || !themes?.edges) return (<Loader />);

  const { id, editContext } = settings;
  const valsToPick: (keyof typeof settings)[] = [
    'platform_title',
    'platform_favicon',
    'platform_email',
    'platform_theme',
    'platform_language',
    'platform_login_message',
    'platform_banner_text',
    'platform_banner_level',
  ];
  const initialValues = valsToPick.reduce((acc, key) => {
    if (key in settings) {
      acc[key] = settings[key];
    }
    return acc;
  }, {} as Record<keyof typeof settings, unknown>);
  const modules = settings.platform_modules;
  const { version, dependencies } = about;
  const isEnterpriseEditionActivated = settings.platform_enterprise_edition.license_enterprise;
  const isEnterpriseEditionByConfig = settings.platform_enterprise_edition.license_by_configuration;
  const isEnterpriseEditionValid = settings.platform_enterprise_edition.license_validated;

  let aiPoweredLabel = t_i18n('Disabled');
  if (settings.platform_ai_enabled) {
    if (settings.platform_ai_has_token) {
      aiPoweredLabel = `${settings.platform_ai_type}`;
    } else {
      aiPoweredLabel = `${settings.platform_ai_type} - ${t_i18n('Missing token')}`;
    }
  }

  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Parameters'), current: true }]} />
      {isEnterpriseEditionActivated && (
        <Grid container={true} spacing={3} style={{ marginBottom: 23 }}>
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t_i18n('Enterprise Edition')}
            </Typography>
            {!isEnterpriseEditionByConfig && (
              <div style={{ float: 'right', marginTop: theme.spacing(-2.6), position: 'relative' }}>
                <DangerZoneBlock
                  type='ce_ee_toggle'
                  sx={{
                    root: { border: 'none', padding: 0, margin: 0 },
                    title: { position: 'absolute', zIndex: 2, left: 4, top: 9, fontSize: 8 },
                  }}
                >
                  {({ disabled }) => (
                    <>
                      <Button
                        size="small"
                        variant="outlined"
                        color='warning'
                        onClick={() => setOpenEEChanges(true)}
                        disabled={disabled}
                        style={{
                          color: isAllowed ? theme.palette.dangerZone.text?.primary : theme.palette.dangerZone.text?.disabled,
                          borderColor: theme.palette.dangerZone.main,
                        }}
                      >
                        {t_i18n('Disable Enterprise Edition')}
                      </Button>
                      <Dialog
                        PaperProps={{ elevation: 1 }}
                        open={openEEChanges}
                        keepMounted
                        TransitionComponent={Transition}
                        onClose={() => setOpenEEChanges(false)}
                      >
                        <DialogTitle>{t_i18n('Disable Enterprise Edition')}</DialogTitle>
                        <DialogContent>
                          <DialogContentText>
                            <Alert
                              severity="warning"
                              variant="outlined"
                              color="dangerZone"
                              style={{ borderColor: theme.palette.dangerZone.main }}
                            >
                              {t_i18n('You are about to disable the "Enterprise Edition" mode. Please note that this action will disable access to certain advanced features (organization segregation, automation, file indexing etc.).')}
                              <br /><br />
                              <strong>{t_i18n('However, your existing data will remain intact and will not be lost.')}</strong>
                            </Alert>
                          </DialogContentText>
                        </DialogContent>
                        <DialogActions>
                          <Button
                            onClick={() => {
                              setOpenEEChanges(false);
                            }}
                          >
                            {t_i18n('Cancel')}
                          </Button>
                          <Button
                            color="secondary"
                            onClick={() => {
                              setOpenEEChanges(false);
                              handleSubmitField(id, 'enterprise_license', '');
                            }}
                          >
                            {t_i18n('Validate')}
                          </Button>
                        </DialogActions>
                      </Dialog>
                    </>
                  )}
                </DangerZoneBlock>
              </div>
            )}
            <div className="clearfix" />
            <Paper
              variant="outlined"
              className='paper-for-grid'
              style={{
                marginTop: theme.spacing(1),
                padding: 20,
                borderRadius: 4,
              }}
            >
              <List style={{ marginTop: -20 }}>
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Organization')} />
                  <ItemBoolean
                    variant="large"
                    neutralLabel={settings.platform_enterprise_edition.license_customer}
                    status={null}
                  />
                </ListItem>
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Creator')} />
                  <ItemBoolean
                    variant="large"
                    neutralLabel={settings.platform_enterprise_edition.license_creator}
                    status={null}
                  />
                </ListItem>
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Scope')} />
                  <ItemBoolean
                    variant="large"
                    neutralLabel={settings.platform_enterprise_edition.license_global ? t_i18n('Global') : t_i18n('Current instance')}
                    status={null}
                  />
                </ListItem>
              </List>
            </Paper>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t_i18n('License')}
            </Typography>
            {!isEnterpriseEditionByConfig && (
              <div style={{ float: 'right', marginTop: theme.spacing(-1.8), position: 'relative' }}>
                <EnterpriseEditionButton inLine={true} />
              </div>
            )}
            <div className="clearfix"/>
            <Paper
              variant="outlined"
              className='paper-for-grid'
              style={{
                marginTop: theme.spacing(1),
                padding: 20,
                borderRadius: 4,
              }}
            >
              <List style={{ marginTop: -20 }}>
                {!settings.platform_enterprise_edition.license_expired && settings.platform_enterprise_edition.license_expiration_prevention && (
                  <ListItem divider={false}>
                    <Alert severity="warning" variant="outlined" style={{ width: '100%' }}>
                      {t_i18n('Your Enterprise Edition license will expire in less than 3 months.')}
                    </Alert>
                  </ListItem>
                )}
                {!settings.platform_enterprise_edition.license_validated && settings.platform_enterprise_edition.license_valid_cert && (
                  <ListItem divider={false}>
                    <Alert severity="error" variant="outlined" style={{ width: '100%' }}>
                      {t_i18n('Your Enterprise Edition license is expired. Please contact your Filigran representative.')}
                    </Alert>
                  </ListItem>
                )}
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Start date')}/>
                  <ItemBoolean
                    variant="xlarge"
                    label={fldt(settings.platform_enterprise_edition.license_start_date)}
                    status={!settings.platform_enterprise_edition.license_expired}
                  />
                </ListItem>
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Expiration date')}/>
                  <ItemBoolean
                    variant="xlarge"
                    label={fldt(settings.platform_enterprise_edition.license_expiration_date)}
                    status={!settings.platform_enterprise_edition.license_expired}
                  />
                </ListItem>
                <ListItem divider={!settings.platform_enterprise_edition.license_expiration_prevention}>
                  <ListItemText primary={t_i18n('License type')}/>
                  <ItemBoolean
                    variant="large"
                    neutralLabel={settings.platform_enterprise_edition.license_type}
                    status={null}
                  />
                </ListItem>
              </List>
            </Paper>
          </Grid>
        </Grid>
      )}
      <Grid container={true} spacing={3}>
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Configuration')}
          </Typography>
          <Paper
            variant="outlined"
            className='paper-for-grid'
            style={{
              marginTop: theme.spacing(1),
              padding: 20,
              borderRadius: 4,
            }}
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
                    onFocus={(name: string) => handleChangeFocus(id, name)}
                    onSubmit={(name: string, value: string | null) => handleSubmitField(id, name, value)}
                    helperText={(
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="platform_title"
                      />
                    )}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="platform_favicon"
                    label={t_i18n('Platform favicon URL')}
                    fullWidth
                    style={{ marginTop: 20 }}
                    onFocus={(name: string) => handleChangeFocus(id, name)}
                    onSubmit={(name: string, value: string | null) => handleSubmitField(id, name, value)}
                    helperText={(
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="platform_favicon"
                      />
                    )}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="platform_email"
                    label={t_i18n('Sender email address')}
                    fullWidth
                    style={{ marginTop: 20 }}
                    onFocus={(name: string) => handleChangeFocus(id, name)}
                    onSubmit={(name: string, value: string | null) => handleSubmitField(id, name, value)}
                    helperText={(
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="platform_email"
                      />
                    )}
                  />
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="platform_theme"
                    label={t_i18n('Default theme')}
                    fullWidth
                    containerstyle={fieldSpacingContainerStyle}
                    onFocus={(name: string) => handleChangeFocus(id, name)}
                    onChange={(name: string, value: string) => handleSubmitField(id, name, value)
                    }
                    helpertext={
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="platform_theme"
                      />
                    }
                  >
                    {themes.edges?.filter((node) => !!node).map(({ node }) => (
                      <MenuItem key={node.id} value={node.name}>
                        {deserializeThemeManifest(node.manifest)
                          ? t_i18n(node.name)
                          : node.name}
                      </MenuItem>
                    ))}
                  </Field>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="platform_language"
                    label={t_i18n('Language')}
                    fullWidth
                    containerstyle={fieldSpacingContainerStyle}
                    onFocus={(name: string) => handleChangeFocus(id, name)}
                    onSubmit={(name: string, value: string | null) => handleSubmitField(id, name, value)}
                    helpertext={(
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="platform_language"
                      />
                    )}
                  >
                    <MenuItem value="auto">
                      <em>{t_i18n('Automatic')}</em>
                    </MenuItem>
                    {availableLanguage.map(({ value, label }) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
                  </Field>
                  <HiddenTypesField />
                </Form>
              )}
            </Formik>
          </Paper>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
            {t_i18n('OpenCTI platform')}
          </Typography>
          <div style={{ float: 'right', marginTop: theme.spacing(-4.5), position: 'relative' }}>
            {!isEnterpriseEditionActivated && (
              <EnterpriseEditionButton inLine={true} />
            )}
          </div>
          <div className="clearfix"/>
          <Paper
            className='paper-for-grid'
            variant="outlined"
            style={{
              marginTop: theme.spacing(1),
              padding: 20,
              borderRadius: 4,
            }}
          >
            <Formik
              onSubmit={() => {}}
              enableReinitialize={true}
              initialValues={initialValues}
              validationSchema={settingsValidation(t_i18n)}
            >
              {() => (
                <Form>
                  <List style={{ marginTop: -20 }}>
                    <ListItem divider={true} style={{ paddingRight: 24 }}>
                      <ListItemText primary={t_i18n('Platform identifier')}/>
                      <ItemCopy content={settings.id} variant="inLine"/>
                    </ListItem>
                    <ListItem divider={true}>
                      <ListItemText primary={t_i18n('Version')}/>
                      <ItemBoolean
                        variant="large"
                        neutralLabel={version}
                        status={null}
                      />
                    </ListItem>
                    <ListItem divider={true}>
                      <ListItemText primary={t_i18n('Edition')}/>
                      <ItemBoolean
                        variant="large"
                        neutralLabel={
                                isEnterpriseEditionValid
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
                        label={aiPoweredLabel}
                        status={settings.platform_ai_enabled && settings.platform_ai_has_token}
                        tooltip={settings.platform_ai_has_token ? `${settings.platform_ai_type} - ${settings.platform_ai_model}` : t_i18n('The token is missing in your platform configuration, please ask your Filigran representative to provide you with it or with on-premise deployment instructions. Your can open a support ticket to do so.')}
                      />
                    </ListItem>
                    <ListItem divider={true}>
                      <ListItemText
                        primary={
                          <>
                            {t_i18n('Remove Filigran logos')}
                            <EEChip/>
                          </>
                              }
                      />
                      <Field
                        component={Switch}
                        variant="standard"
                        name="platform_whitemark"
                        disabled={!isEnterpriseEditionValid}
                        checked={
                                  settings.platform_whitemark
                                  && isEnterpriseEditionValid
                              }
                        onChange={(_: unknown, value: string | null) => handleSubmitField(
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
          <SettingsMessages settings={settings}/>
        </Grid>
        <Grid item xs={4}>
          <SettingsAnalytics
            settings={settings}
            handleChangeFocus={handleChangeFocus}
            handleSubmitField={handleSubmitField}
            isEnterpriseEdition={isEnterpriseEditionValid}
          />
        </Grid>
        <Grid item xs={8}>
          <Themes handleRefetch={handleRefetch} />
        </Grid>
        <Grid item xs={4}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Tools')}
          </Typography>
          <Paper
            className={'paper-for-grid'}
            variant="outlined"
            style={{
              marginTop: theme.spacing(1),
              padding: 20,
              borderRadius: 4,
            }}
          >
            <List style={{ marginTop: -20 }}>
              {(modules ?? []).map((module) => {
                const isEeModule = ['ACTIVITY_MANAGER', 'PLAYBOOK_MANAGER', 'FILE_INDEX_MANAGER'].includes(module.id);
                let status: string | boolean = module.enable;
                if (!isEnterpriseEditionActivated && isEeModule) {
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
};

export default Settings;
