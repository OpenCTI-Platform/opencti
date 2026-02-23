import React from 'react';
import { Field, useFormikContext } from 'formik';
import Box from '@mui/material/Box';
import FormControl from '@mui/material/FormControl';
import FormHelperText from '@mui/material/FormHelperText';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import { useTheme } from '@mui/styles';
import TextField from '../../../../components/TextField';
import Tag from '../../../../components/common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import type { SecretSource } from './__generated__/SSODefinitionEditionFragment.graphql';

/** Compatible with Relay fragment (SecretSource includes "%future added value"). */
export type SecretInfo = {
  source: SecretSource;
  external_secret_name?: string | null;
};

/** keep = leave as-is; store = set new value (new_value_cleartext); use_external_secret = use a secret by name (external_secret_name). */
export type SecretAction = 'keep' | 'store' | 'use_external_secret';

interface SecretFieldControlProps {
  secretInfo: SecretInfo | null | undefined;
  namePrefix: string;
  label: string;
  isEditing: boolean;
  /** Secrets available for external ref (provider_name + secret_name). */
  availableSecrets: ReadonlyArray<{ readonly provider_name: string; readonly secret_name: string }>;
  /** Use multiline text field (e.g. for SAML private keys). */
  multiline?: boolean;
  /** Style for the container (e.g. marginTop to align with other fields). */
  style?: React.CSSProperties;
}

export const SecretFieldControl: React.FC<SecretFieldControlProps> = ({
  secretInfo,
  namePrefix,
  label,
  isEditing,
  availableSecrets,
  multiline = false,
  style,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { values, setFieldValue, errors, touched } = useFormikContext<Record<string, unknown>>();
  const action = (values[`${namePrefix}_action`] as SecretAction) ?? (isEditing ? 'keep' : 'store');
  const secretName = (values[`${namePrefix}_secret_name`] as string) ?? '';
  const actionError = touched[`${namePrefix}_new_value`] && errors[`${namePrefix}_new_value`];

  const isExternal = secretInfo?.source === 'EXTERNAL';
  const currentSecret = isExternal && secretInfo?.external_secret_name
    ? availableSecrets.find((s) => s.secret_name === secretInfo.external_secret_name)
    : availableSecrets.find((s) => s.secret_name === secretName);
  const displayLabel = currentSecret
    ? `${currentSecret.secret_name} (${currentSecret.provider_name})`
    : (secretInfo?.external_secret_name ?? secretName) || null;

  if (isExternal && !isEditing) {
    return (
      <Box sx={style}>
        <InputLabel shrink sx={{ position: 'relative', mb: 0.5, display: 'block' }}>
          {label}
        </InputLabel>
        <Tag
          label={displayLabel ? `${t_i18n('External secret')}: ${displayLabel}` : t_i18n('Externally managed')}
          color={theme.palette.primary.main}
        />
      </Box>
    );
  }

  const showKeepOption = isEditing && !isExternal;

  return (
    <Box sx={style}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 2,
          flexWrap: (action === 'store' && multiline) || action === 'use_external_secret' ? 'wrap' : 'nowrap',
        }}
      >
        <FormControl variant="standard" sx={{ minWidth: 200, flexShrink: 0 }}>
          <InputLabel shrink>{label}</InputLabel>
          <Select
            value={isExternal && action === 'keep' ? 'use_external_secret' : action}
            onChange={(e) => {
              const v = e.target.value as SecretAction;
              setFieldValue(`${namePrefix}_action`, v);
              if (v !== 'store') setFieldValue(`${namePrefix}_new_value`, '');
              if (v !== 'use_external_secret') {
                setFieldValue(`${namePrefix}_secret_name`, '');
              } else if (availableSecrets.length > 0 && !secretName) {
                setFieldValue(`${namePrefix}_secret_name`, availableSecrets[0].secret_name);
              }
            }}
            label={label}
          >
            {showKeepOption && (
              <MenuItem value="keep">{t_i18n('Keep existing secret')}</MenuItem>
            )}
            <MenuItem value="store">{t_i18n('Set a new secret')}</MenuItem>
            <MenuItem value="use_external_secret">{t_i18n('Use external secret')}</MenuItem>
          </Select>
        </FormControl>
        {action === 'store' && (
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Field
              component={TextField}
              variant="standard"
              name={`${namePrefix}_new_value`}
              label={isEditing ? t_i18n('New value (leave empty to remove)') : t_i18n('Value')}
              fullWidth
              type="password"
              multiline={multiline}
              rows={multiline ? 4 : undefined}
              error={!!actionError}
            />
            {actionError && (
              <FormHelperText error>{String(actionError)}</FormHelperText>
            )}
          </Box>
        )}
        {action === 'use_external_secret' && (
          <FormControl variant="standard" sx={{ minWidth: 260 }}>
            <InputLabel shrink>{t_i18n('External secret')}</InputLabel>
            <Select
              value={secretName || (availableSecrets[0]?.secret_name ?? '')}
              onChange={(e) => setFieldValue(`${namePrefix}_secret_name`, e.target.value)}
              label={t_i18n('External secret')}
              displayEmpty
            >
              {availableSecrets.length === 0 ? (
                <MenuItem value="" disabled>{t_i18n('No external secrets configured')}</MenuItem>
              ) : (
                availableSecrets.map((s) => (
                  <MenuItem key={s.secret_name} value={s.secret_name}>
                    {s.secret_name} ({s.provider_name})
                  </MenuItem>
                ))
              )}
            </Select>
          </FormControl>
        )}
      </Box>
    </Box>
  );
};

export default SecretFieldControl;
