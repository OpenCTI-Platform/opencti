import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import getEEWarningMessage from '@components/settings/EEActivation';
import { SettingsFieldPatchMutation$data } from '@components/settings/__generated__/SettingsFieldPatchMutation.graphql';
import ThemeManager, { refetchableThemesQuery } from '@components/settings/themes/ThemeManager';
import { ThemeManager_themes$key } from '@components/settings/themes/__generated__/ThemeManager_themes.graphql';
import { Switch } from '@mui/material';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import { useTheme } from '@mui/styles';
import { Field, Form, Formik } from 'formik';
import React, { ChangeEvent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useRefetchableFragment } from 'react-relay';
import * as Yup from 'yup';
import { availableLanguage } from '../../../components/AppIntlProvider';
import Breadcrumbs from '../../../components/Breadcrumbs';
import ItemBoolean from '../../../components/ItemBoolean';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useSubscriptionFocusHelper } from '../../../components/Subscription';
import TextField from '../../../components/TextField';
import type { Theme } from '../../../components/Theme';
import Card from '../../../components/common/card/Card';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useSensitiveModifications from '../../../utils/hooks/useSensitiveModifications';
import DangerZoneChip from '../common/danger_zone/DangerZoneChip';
import EEChip from '../common/entreprise_edition/EEChip';
import EnterpriseEditionButton from '../common/entreprise_edition/EnterpriseEditionButton';
import { SettingsQuery } from './__generated__/SettingsQuery.graphql';
import HiddenTypesField from './hidden_types/HiddenTypesField';
import SettingsAnalytics from './settings_analytics/SettingsAnalytics';
import SettingsMessages from './settings_messages/SettingsMessages';
import SettingsMapSource from './settings_map_source/SettingsMapSource';
import SettingsManagers from './settings_managers/SettingsManagers';
import SettingsDependencies from './settings_platform/SettingsDependencies';
import SettingsInfoRow from './settings_platform/SettingsInfoRow';
import SettingsPlatformSummary from './settings_platform/SettingsPlatformSummary';
import { useChatbot } from '@components/chatbox/ChatbotContext';

const twoColumnsSx = { display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 3 };
const wideNarrowSx = { display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 1fr)', gap: 3 };

const AI_TYPE_MAP: Record<string, string> = {
  mistralai: 'MistralAI',
  openai: 'OpenAI',
  azureopenai: 'AzureOpenAI',
};

const formatAIType = (type: string | null | undefined): string => {
  if (!type) return '';
  const parts = type.split(' ');
  const lastPart = parts[parts.length - 1].toLowerCase();
  parts[parts.length - 1] = AI_TYPE_MAP[lastPart] ?? parts[parts.length - 1];
  return parts.join(' ');
};

const settingsQuery = graphql`
  query SettingsQuery {
    settings {
      id
      platform_title
      platform_favicon
      platform_email
      platform_email_configurable
      platform_theme {
        id
        name
      }
      platform_language
      platform_type
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
      filigran_chatbot_ai_cgu_status
      platform_map_custom_file {
        name
        size
      }
      platform_map_countries_custom_file {
        name
        size
      }
    }
    about {
      version
      dependencies {
        name
        version
      }
    }
    ...ThemeManager_themes
  }
`;

interface SettingsComponentProps {
  queryRef: PreloadedQuery<SettingsQuery>;
}

export const settingsMutationFieldPatch = graphql`
  mutation SettingsFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        platform_title
        platform_favicon
        platform_email
        platform_email_configurable
        platform_theme {
          id
          name
        }
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

const SettingsComponent = ({ queryRef }: SettingsComponentProps) => {
  const theme = useTheme<Theme>();

  const [openEEChanges, setOpenEEChanges] = useState(false);
  const { xtmOneConfigured } = useChatbot();
  const { isSensitive: isEnterpriseToggleSensitive, isAllowed: isEnterpriseToggleAllowed } = useSensitiveModifications('ce_ee_toggle');

  const { t_i18n, fldt } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  const { settings, about } = usePreloadedQuery<SettingsQuery>(settingsQuery, queryRef);

  const data = usePreloadedQuery<SettingsQuery>(settingsQuery, queryRef);
  const [{ themes }, refetch] = useRefetchableFragment<SettingsQuery, ThemeManager_themes$key>(
    refetchableThemesQuery,
    data,
  );

  const { id, editContext } = settings;
  const focusHelper = useSubscriptionFocusHelper(editContext);

  const initialValues = {
    platform_title: settings.platform_title,
    platform_favicon: settings.platform_favicon,
    platform_email: settings.platform_email,
    platform_theme: settings.platform_theme?.id,
    platform_language: settings.platform_language,
    platform_login_message: settings.platform_login_message,
    platform_banner_text: settings.platform_banner_text,
    platform_banner_level: settings.platform_banner_level,
  };

  const modules = settings.platform_modules;
  const { version, dependencies } = about || { version: '', dependencies: [] };
  const isEnterpriseEditionActivated = settings.platform_enterprise_edition.license_enterprise;
  const isEnterpriseEditionByConfig = settings.platform_enterprise_edition.license_by_configuration;
  const isEnterpriseEditionValid = settings.platform_enterprise_edition.license_validated;

  setTitle(t_i18n('Parameters | Settings'));

  // generate AI Powered label and tooltip
  let aiPoweredLabel;
  let aiPoweredTooltip;
  const formattedAIType = formatAIType(settings.platform_ai_type);
  if (!isEnterpriseEditionValid) {
    aiPoweredLabel = t_i18n('Disabled');
    aiPoweredTooltip = t_i18n('You should activate EE to use this feature');
  } else if (!settings.platform_ai_enabled) {
    aiPoweredLabel = t_i18n('Disabled');
    aiPoweredTooltip = t_i18n('AI is not enabled');
  } else if (settings.platform_ai_has_token) {
    aiPoweredLabel = formattedAIType;
    aiPoweredTooltip = `${formattedAIType} - ${settings.platform_ai_model}`;
  } else {
    aiPoweredLabel = `${formattedAIType} - ${t_i18n('Missing token')}`;
    aiPoweredTooltip = t_i18n('The token is missing in your platform configuration, please ask your Filigran representative to provide you with it or with on-premise deployment instructions. You can open a support ticket to do so.');
  };

  const settingsValidation = () => Yup.object().shape({
    platform_title: Yup.string().required(t_i18n('This field is required')),
    platform_favicon: Yup.string().nullable(),
    platform_email: Yup.string()
      .required(t_i18n('This field is required'))
      .email(t_i18n('The value must be an email address')),
    platform_theme: Yup.string().nullable(),
    platform_language: Yup.string().nullable(),
    platform_whitemark: Yup.string().nullable(),
    enterprise_license: Yup.string().nullable(),
    platform_login_message: Yup.string().nullable(),
    platform_banner_text: Yup.string().nullable(),
    platform_banner_level: Yup.string().nullable(),
    analytics_google_analytics_v4: Yup.string().nullable(),
  });

  const handleRefetch = () => refetch(
    {},
    { fetchPolicy: 'network-only' },
  );

  const [commitSettingsFocus] = useApiMutation(settingsFocus);
  const [commitField] = useApiMutation(settingsMutationFieldPatch);

  const handleChangeFocus = (name: string) => {
    commitSettingsFocus({
      variables: {
        id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const isLtsPlatform = settings.platform_type === 'LTS';
  const handleSubmitField = async (name: string, value: string | boolean) => {
    let finalValue = value;
    if (
      typeof finalValue === 'string'
      && [
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

    settingsValidation()
      .validateAt(name, { [name]: finalValue })
      .then(() => {
        commitField({
          variables: { id, input: { key: name, value: finalValue || '' } },
          onCompleted: (response) => {
            const data = response as SettingsFieldPatchMutation$data;
            // If platform is LTS but license is no longer valid, need to refresh to force the license.
            if (isLtsPlatform && !data.settingsEdit?.fieldPatch?.platform_enterprise_edition.license_validated) {
              window.location.reload();
            }
          },
        });
      })
      .catch(() => false);
  };

  return (
    <div style={{ height: '100%', scrollbarWidth: 'none' }} data-testid="setting-page">
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Parameters'), current: true }]} />
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, marginBottom: 10 }}>
        <SettingsPlatformSummary
          platformId={settings.id}
          version={version}
          isEnterpriseEditionValid={isEnterpriseEditionValid}
          instancesNumber={settings.platform_cluster.instances_number}
          modules={modules ?? []}
          ai={xtmOneConfigured ? null : {
            label: aiPoweredLabel,
            tooltip: aiPoweredTooltip,
            status: isEnterpriseEditionValid && settings.platform_ai_enabled && settings.platform_ai_has_token,
          }}
          action={!isEnterpriseEditionActivated && (
            <EnterpriseEditionButton inLine={true} />
          )}
        />

        {isEnterpriseEditionActivated && (
          <>
            <Box sx={twoColumnsSx}>
              <Card
                title={t_i18n('Enterprise Edition')}
                padding="horizontal"
                data-testid="settings-enterprise-edition"
                action={!isEnterpriseEditionByConfig && (
                // keepMui: the 26 px of the license button on the same row, which renders through MUI
                  <Button
                    size="small"
                    variant="secondary"
                    intent="destructive"
                    keepMui
                    disabled={isEnterpriseToggleSensitive && !isEnterpriseToggleAllowed}
                    onClick={() => setOpenEEChanges(true)}
                  >
                    {t_i18n('Disable Enterprise Edition')}
                  </Button>
                )}
              >
                <SettingsInfoRow label={t_i18n('Organization')}>
                  <ItemBoolean
                    neutralLabel={settings.platform_enterprise_edition.license_customer}
                    status={null}
                  />
                </SettingsInfoRow>
                <SettingsInfoRow label={t_i18n('Creator')}>
                  <ItemBoolean
                    neutralLabel={settings.platform_enterprise_edition.license_creator}
                    status={null}
                    labelTextTransform="none"
                  />
                </SettingsInfoRow>
                <SettingsInfoRow label={t_i18n('Scope')} divider={false}>
                  <ItemBoolean
                    neutralLabel={settings.platform_enterprise_edition.license_global ? t_i18n('Global') : t_i18n('Current instance')}
                    status={null}
                  />
                </SettingsInfoRow>
              </Card>
              <Card
                title={t_i18n('License')}
                padding="horizontal"
                data-testid="settings-license"
                action={!isEnterpriseEditionByConfig && (
                  <EnterpriseEditionButton inLine={true} />
                )}
              >
                {!settings.platform_enterprise_edition.license_expired && settings.platform_enterprise_edition.license_expiration_prevention && (
                  <Alert severity="warning" variant="outlined" sx={{ marginY: 1 }}>
                    {t_i18n('Your Enterprise Edition license will expire in less than 3 months.')}
                  </Alert>
                )}
                {!settings.platform_enterprise_edition.license_validated && settings.platform_enterprise_edition.license_valid_cert && (
                  <Alert severity="error" variant="outlined" sx={{ marginY: 1 }}>
                    {t_i18n('Your Enterprise Edition license is expired. Please contact your Filigran representative.')}
                  </Alert>
                )}
                <SettingsInfoRow label={t_i18n('Start date')}>
                  <ItemBoolean
                    label={fldt(settings.platform_enterprise_edition.license_start_date)}
                    status={!settings.platform_enterprise_edition.license_expired}
                  />
                </SettingsInfoRow>
                <SettingsInfoRow label={t_i18n('Expiration date')}>
                  <ItemBoolean
                    label={fldt(settings.platform_enterprise_edition.license_expiration_date)}
                    status={!settings.platform_enterprise_edition.license_expired}
                  />
                </SettingsInfoRow>
                <SettingsInfoRow label={t_i18n('License type')} divider={false}>
                  <ItemBoolean
                    neutralLabel={settings.platform_enterprise_edition.license_type}
                    status={null}
                    labelTextTransform="uppercase"
                  />
                </SettingsInfoRow>
              </Card>
            </Box>
            <Dialog
              open={openEEChanges}
              onClose={() => setOpenEEChanges(false)}
              title={isEnterpriseToggleSensitive ? (
                <Box component="span" sx={{ display: 'inline-flex', alignItems: 'center', gap: 1 }}>
                  {t_i18n('Disable Enterprise Edition')}
                  <DangerZoneChip />
                </Box>
              ) : t_i18n('Disable Enterprise Edition')}
            >
              <DialogContentText component="div">
                <Alert
                  severity="warning"
                  variant="outlined"
                  color="dangerZone"
                  style={{ borderColor: theme.palette.dangerZone.main }}
                >
                  {t_i18n(getEEWarningMessage(isLtsPlatform))}
                  <br /><br />
                  <strong>{t_i18n('However, your existing data will remain intact and will not be lost.')}</strong>
                </Alert>
              </DialogContentText>
              <DialogActions>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setOpenEEChanges(false);
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={() => {
                    setOpenEEChanges(false);
                    handleSubmitField('enterprise_license', '');
                  }}
                >
                  {t_i18n('Validate')}
                </Button>
              </DialogActions>
            </Dialog>
          </>
        )}

        <Box sx={twoColumnsSx}>
          <Card title={t_i18n('Configuration')} data-testid="settings-configuration">
            <Formik
              onSubmit={() => {
              }}
              enableReinitialize={true}
              initialValues={initialValues}
              validationSchema={settingsValidation()}
            >
              {() => (
                <Form>
                  <Field
                    component={TextField}
                    variant="outlined"
                    name="platform_title"
                    label={t_i18n('Platform title')}
                    fullWidth
                    onFocus={(name: string) => handleChangeFocus(name)}
                    onSubmit={(name: string, value: string) => handleSubmitField(name, value)}
                    helperText={focusHelper('platform_title')}
                  />
                  <Field
                    component={TextField}
                    variant="outlined"
                    name="platform_favicon"
                    label={t_i18n('Platform favicon URL')}
                    fullWidth
                    className="mt-5"
                    onFocus={(name: string) => handleChangeFocus(name)}
                    onSubmit={(name: string, value: string) => handleSubmitField(name, value)}
                    helperText={focusHelper('platform_favicon')}
                  />
                  <Field
                    component={TextField}
                    variant="outlined"
                    name="platform_email"
                    disabled={!settings.platform_email_configurable}
                    label={t_i18n('Sender email address')}
                    fullWidth
                    className="mt-5"
                    onFocus={(name: string) => handleChangeFocus(name)}
                    onSubmit={(name: string, value: string) => handleSubmitField(name, value)}
                    helperText={focusHelper('platform_email')}
                  />
                </Form>
              )}
            </Formik>
            <div style={fieldSpacingContainerStyle}>
              <SettingsAnalytics
                settings={settings}
                handleChangeFocus={handleChangeFocus}
                handleSubmitField={handleSubmitField}
                isEnterpriseEdition={isEnterpriseEditionValid}
              />
            </div>
          </Card>

          <Card title={t_i18n('Appearance')} data-testid="settings-appearance">
            <Formik
              onSubmit={() => {}}
              enableReinitialize={true}
              initialValues={initialValues}
              validationSchema={settingsValidation()}
            >
              {() => (
                <Form>
                  <Field
                    component={SelectFieldFds}
                    name="platform_theme"
                    label={t_i18n('Default theme')}
                    fullWidth
                    onFocus={(name: string) => handleChangeFocus(name)}
                    onChange={(name: string, value: string) => {
                      handleSubmitField(name, value);
                    }}
                    helpertext={focusHelper('platform_theme')}
                  >
                    {themes?.edges?.filter((node) => !!node).map(({ node }) => (
                      <SelectItem
                        key={node.id}
                        value={node.id}
                        data-testid={`${node.name}-li`}
                      >
                        {node.name}
                      </SelectItem>
                    ))}
                  </Field>
                  <Field
                    component={SelectFieldFds}
                    name="platform_language"
                    label={t_i18n('Language')}
                    fullWidth
                    containerstyle={fieldSpacingContainerStyle}
                    onFocus={(name: string) => handleChangeFocus(name)}
                    onChange={(name: string, value: string) => handleSubmitField(name, value)}
                    helpertext={focusHelper('platform_language')}
                  >
                    <SelectItem value="auto">
                      <em>{t_i18n('Automatic')}</em>
                    </SelectItem>
                    {availableLanguage.map(({ value, label }) => <SelectItem key={value} value={value}>{label}</SelectItem>)}
                  </Field>
                  <HiddenTypesField />
                  <div style={fieldSpacingContainerStyle}>
                    <SettingsInfoRow
                      data-testid="settings-whitemark"
                      divider={false}
                      size="field"
                      label={(
                        <>
                          {t_i18n('Remove Filigran logos')}
                          <EEChip size="sm" />
                        </>
                      )}
                    >
                      <Field
                        component={Switch}
                        variant="outlined"
                        name="platform_whitemark"
                        disabled={!isEnterpriseEditionValid}
                        checked={
                          settings.platform_whitemark
                          && isEnterpriseEditionValid
                        }
                        inputProps={{ 'aria-label': t_i18n('Remove Filigran logos') }}
                        onChange={(_event: ChangeEvent<HTMLInputElement>, value: boolean) => handleSubmitField(
                          'platform_whitemark',
                          value,
                        )}
                      />
                    </SettingsInfoRow>
                  </div>
                </Form>
              )}
            </Formik>
          </Card>
        </Box>

        <Box sx={wideNarrowSx}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <SettingsMessages settings={settings} />
            <SettingsMapSource settings={settings} />
          </Box>
          <ThemeManager
            handleRefetch={handleRefetch}
            defaultTheme={settings.platform_theme}
          />
        </Box>

        <SettingsDependencies dependencies={dependencies} />

        <SettingsManagers
          modules={modules ?? []}
          isEnterpriseEditionValid={isEnterpriseEditionValid}
        />
      </Box>
    </div>
  );
};

const Settings = () => {
  const queryRef = useQueryLoading<SettingsQuery>(settingsQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <SettingsComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default Settings;
