import React from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import { InfoOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import { Icon, IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import type { LocalStrategyFormQuery } from './__generated__/LocalStrategyFormQuery.graphql';
import type { LocalStrategyFormMutation } from './__generated__/LocalStrategyFormMutation.graphql';

const localStrategyFormQuery = graphql`
  query LocalStrategyFormQuery {
    settings {
      id
      local_auth {
        enabled
      }
      password_policy_min_length
      password_policy_max_length
      password_policy_min_symbols
      password_policy_min_numbers
      password_policy_min_words
      password_policy_min_lowercase
      password_policy_min_uppercase
      password_policy_validity_days
      local_auth_lockout_enabled
      local_auth_lockout_max_attempts
      local_auth_lockout_window
      local_auth_lockout_duration
      local_auth_lockout_max_duration
      platform_enterprise_edition {
        license_validated
      }
      platform_providers {
        name
        type
        strategy
        provider
      }
      headers_auth {
        enabled
      }
      platform_https_enabled
      is_authentication_by_env
    }
  }
`;

const localStrategyFormMutation = graphql`
  mutation LocalStrategyFormMutation($id: ID!, $input: LocalAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateLocalAuth(input: $input) {
        id
        local_auth {
          enabled
        }
        password_policy_min_length
        password_policy_max_length
        password_policy_min_symbols
        password_policy_min_numbers
        password_policy_min_words
        password_policy_min_lowercase
        password_policy_min_uppercase
        password_policy_validity_days
        local_auth_lockout_enabled
        local_auth_lockout_max_attempts
        local_auth_lockout_window
        local_auth_lockout_duration
        local_auth_lockout_max_duration
      }
    }
  }
`;

type Translate = (message: string, options?: { values: Record<string, number> }) => string;

// Upper bounds of the lockout policy, mirrored from setting-auth.ts
const LOCKOUT_MAX_ATTEMPTS_LIMIT = 100;
const LOCKOUT_WINDOW_LIMIT = 43200; // minutes, 30 days
const LOCKOUT_MAX_DURATION_LIMIT = 180; // minutes, locks are capped to 3h

// Lockout values are only checked when the lockout is enabled, as their fields are hidden otherwise
// A cleared field holds '', which is read as missing rather than as NaN
const lockoutNumberSchema = (t_i18n: Translate, limit: number) => Yup.number()
  .transform((value, originalValue) => (originalValue === '' ? undefined : value))
  .typeError(t_i18n('The value must be a number'))
  .when('local_auth_lockout_enabled', {
    is: true,
    then: (schema) => schema
      .required(t_i18n('This field is required'))
      .integer(t_i18n('The value must be an integer'))
      .min(1, t_i18n('The value must be greater than or equal to 1'))
      .max(limit, t_i18n('The value must be less than or equal to {limit}', { values: { limit } })),
  });

const localStrategyValidation = (t_i18n: Translate) => Yup.object().shape({
  enabled: Yup.boolean(),
  password_policy_min_length: Yup.number(),
  password_policy_max_length: Yup.number(),
  password_policy_min_symbols: Yup.number(),
  password_policy_min_numbers: Yup.number(),
  password_policy_min_words: Yup.number(),
  password_policy_min_lowercase: Yup.number(),
  password_policy_min_uppercase: Yup.number(),
  password_policy_validity_days: Yup.number(),
  local_auth_lockout_enabled: Yup.boolean(),
  local_auth_lockout_max_attempts: lockoutNumberSchema(t_i18n, LOCKOUT_MAX_ATTEMPTS_LIMIT),
  local_auth_lockout_window: lockoutNumberSchema(t_i18n, LOCKOUT_WINDOW_LIMIT),
  local_auth_lockout_duration: lockoutNumberSchema(t_i18n, LOCKOUT_MAX_DURATION_LIMIT),
  local_auth_lockout_max_duration: lockoutNumberSchema(t_i18n, LOCKOUT_MAX_DURATION_LIMIT)
    // Only compared to a valid first duration, whose own field reports any other error
    .when(['local_auth_lockout_enabled', 'local_auth_lockout_duration'], {
      is: (lockoutEnabled: boolean, duration?: number) => lockoutEnabled && duration !== undefined
        && Number.isFinite(duration) && duration <= LOCKOUT_MAX_DURATION_LIMIT,
      then: (schema) => schema.min(
        Yup.ref('local_auth_lockout_duration'),
        t_i18n('The maximum lock duration must be greater than or equal to the first lock duration'),
      ),
    }),
});

interface LocalStrategyFormProps {
  onCancel: () => void;
}

const LocalStrategyForm = ({ onCancel }: LocalStrategyFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { isFeatureEnable } = useHelper();
  const isLockoutFeatureEnabled = isFeatureEnable('LOCAL_AUTH_LOCKOUT');
  const data = useLazyLoadQuery<LocalStrategyFormQuery>(localStrategyFormQuery, {});
  const settings = data.settings;
  const isConfigurationFromEnv = settings.is_authentication_by_env ?? false;

  const [commitMutation] = useApiMutation<LocalStrategyFormMutation>(
    localStrategyFormMutation,
    undefined,
    { successMessage: t_i18n('Authentication successfully updated') },
  );

  const localAuth = settings.local_auth;

  const eeActive = settings.platform_enterprise_edition?.license_validated === true;
  const isHttpsEnabled = settings.platform_https_enabled;
  const hasNonLocalProvider = (settings.platform_providers ?? []).some(
    (p) => p.provider !== 'local' && (p.provider !== 'cert' || isHttpsEnabled),
  );
  const hasHeaderAuth = settings.headers_auth?.enabled === true;
  const canDisableLocal = eeActive && (hasNonLocalProvider || hasHeaderAuth);

  const initialValues = {
    enabled: localAuth?.enabled ?? true,
    password_policy_min_length: settings.password_policy_min_length ?? 0,
    password_policy_max_length: settings.password_policy_max_length ?? 0,
    password_policy_min_symbols: settings.password_policy_min_symbols ?? 0,
    password_policy_min_numbers: settings.password_policy_min_numbers ?? 0,
    password_policy_min_words: settings.password_policy_min_words ?? 0,
    password_policy_min_lowercase: settings.password_policy_min_lowercase ?? 0,
    password_policy_min_uppercase: settings.password_policy_min_uppercase ?? 0,
    password_policy_validity_days: settings.password_policy_validity_days ?? 0,
    local_auth_lockout_enabled: settings.local_auth_lockout_enabled ?? false,
    // The back end always returns a value, falling back to its own defaults
    local_auth_lockout_max_attempts: settings.local_auth_lockout_max_attempts ?? '',
    local_auth_lockout_window: settings.local_auth_lockout_window ?? '',
    local_auth_lockout_duration: settings.local_auth_lockout_duration ?? '',
    local_auth_lockout_max_duration: settings.local_auth_lockout_max_duration ?? '',
  };

  const handleSubmit = (
    values: typeof initialValues,
    { setSubmitting }: { setSubmitting: (flag: boolean) => void },
  ) => {
    setSubmitting(true);
    // When the lockout is disabled, its hidden values are left untouched
    const lockoutInput = values.local_auth_lockout_enabled
      ? {
          local_auth_lockout_enabled: true,
          local_auth_lockout_max_attempts: Number(values.local_auth_lockout_max_attempts),
          local_auth_lockout_window: Number(values.local_auth_lockout_window),
          local_auth_lockout_duration: Number(values.local_auth_lockout_duration),
          local_auth_lockout_max_duration: Number(values.local_auth_lockout_max_duration),
        }
      : { local_auth_lockout_enabled: false };
    commitMutation({
      variables: {
        id: settings.id,
        input: {
          enabled: values.enabled,
          password_policy_min_length: Number(values.password_policy_min_length) || 0,
          password_policy_max_length: Number(values.password_policy_max_length) || 0,
          password_policy_min_symbols: Number(values.password_policy_min_symbols) || 0,
          password_policy_min_numbers: Number(values.password_policy_min_numbers) || 0,
          password_policy_min_words: Number(values.password_policy_min_words) || 0,
          password_policy_min_lowercase: Number(values.password_policy_min_lowercase) || 0,
          password_policy_min_uppercase: Number(values.password_policy_min_uppercase) || 0,
          password_policy_validity_days: Number(values.password_policy_validity_days) || 0,
          ...(isLockoutFeatureEnabled && lockoutInput),
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        onCancel();
      },
      onError: () => {
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik
      enableReinitialize
      initialValues={initialValues}
      validationSchema={localStrategyValidation(t_i18n)}
      onSubmit={handleSubmit}
      onReset={onCancel}
    >
      {({ handleReset, submitForm, isSubmitting, dirty, values }) => (
        <Form>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Field
              component={SwitchField}
              type="checkbox"
              name="enabled"
              label={t_i18n('Enable local authentication')}
              disabled={isConfigurationFromEnv || (!canDisableLocal && initialValues.enabled)}
            />
            {isConfigurationFromEnv && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <InfoOutlined fontSize="small" color="primary" sx={{ ml: 1, cursor: 'default' }} />
                </TooltipTrigger>
                <TooltipContent>{t_i18n('Local authentication cannot be changed when authentication is managed by environment configuration')}</TooltipContent>
              </Tooltip>
            )}
            {!canDisableLocal && initialValues.enabled && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <InfoOutlined fontSize="small" color="primary" sx={{ ml: 1, cursor: 'default' }} />
                </TooltipTrigger>
                <TooltipContent>{t_i18n('Local authentication cannot be disabled when no other authentication provider is enabled')}</TooltipContent>
              </Tooltip>
            )}
          </Box>
          <Typography variant="h4" gutterBottom style={{ marginBottom: 20, marginTop: 20 }}>
            {t_i18n('Local password policies')}
          </Typography>
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            name="password_policy_min_length"
            label={t_i18n('Number of chars must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            className="mt-5"
            name="password_policy_max_length"
            label={`${t_i18n('Number of chars must be lower or equals to')} (${t_i18n('0 equals no maximum')})`}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            className="mt-5"
            name="password_policy_min_symbols"
            label={t_i18n('Number of symbols must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            className="mt-5"
            name="password_policy_min_numbers"
            label={t_i18n('Number of digits must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            className="mt-5"
            name="password_policy_min_words"
            label={t_i18n('Number of words (split on hyphen, space) must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            className="mt-5"
            name="password_policy_min_lowercase"
            label={t_i18n('Number of lowercase chars must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            className="mt-5"
            name="password_policy_min_uppercase"
            label={t_i18n('Number of uppercase chars must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="outlined"
            className="mt-5"
            name="password_policy_validity_days"
            label={`${t_i18n('Password validity duration in days')} (${t_i18n('0 equals unlimited')})`}
            fullWidth
          />
          {isLockoutFeatureEnabled && (
            <>
              <Typography variant="h4" gutterBottom style={{ marginBottom: 20, marginTop: 20 }}>
                {t_i18n('Account lockout policy')}
              </Typography>
              <Field
                component={SwitchField}
                type="checkbox"
                name="local_auth_lockout_enabled"
                label={t_i18n('Temporarily lock accounts after repeated failed login attempts')}
              />
              {values.local_auth_lockout_enabled && (
                <>
                  <Field
                    component={TextField}
                    type="number"
                    variant="outlined"
                    className="mt-5"
                    name="local_auth_lockout_max_attempts"
                    label={t_i18n('Number of failed login attempts before lock')}
                    fullWidth
                  />
                  <Field
                    component={TextField}
                    type="number"
                    variant="outlined"
                    className="mt-5"
                    name="local_auth_lockout_window"
                    label={t_i18n('Failed login attempts counter reset after (minutes)')}
                    fullWidth
                  />
                  <Field
                    component={TextField}
                    type="number"
                    variant="outlined"
                    className="mt-5"
                    name="local_auth_lockout_duration"
                    label={t_i18n('First lock duration (minutes)')}
                    fullWidth
                    infoTooltip={(
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <IconButton
                            icon={<Icon name="info" size={16} className="text-feedback-info-primary" />}
                            aria-label={t_i18n('More information')}
                            variant="default"
                            priority="tertiary"
                            size="sm"
                          />
                        </TooltipTrigger>
                        <TooltipContent>{t_i18n('The lock duration increases exponentially with each new lock, up to the maximum lock duration')}</TooltipContent>
                      </Tooltip>
                    )}
                  />
                  <Field
                    component={TextField}
                    type="number"
                    variant="outlined"
                    className="mt-5"
                    name="local_auth_lockout_max_duration"
                    label={t_i18n('Maximum lock duration (minutes)')}
                    fullWidth
                  />
                </>
              )}
            </>
          )}
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting || !dirty}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Update')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default LocalStrategyForm;
