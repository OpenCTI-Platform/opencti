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
  external_provider_name?: string | null;
};

export type SecretAction = 'keep' | 'override';

interface SecretFieldControlProps {
  /** When EXTERNAL, only the chip is shown. Otherwise dropdown + optional field. */
  secretInfo: SecretInfo | null | undefined;
  /** Formik field name prefix. We use `${namePrefix}_action` and `${namePrefix}_new_value`. */
  namePrefix: string;
  label: string;
  isEditing: boolean;
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
  multiline = false,
  style,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { values, setFieldValue, errors, touched } = useFormikContext<Record<string, unknown>>();
  const action = (values[`${namePrefix}_action`] as SecretAction) ?? (isEditing ? 'keep' : 'override');
  const actionError = touched[`${namePrefix}_new_value`] && errors[`${namePrefix}_new_value`];

  if (secretInfo?.source === 'EXTERNAL') {
    const sourceLabel = secretInfo.external_provider_name ?? 'external';
    return (
      <Box sx={style}>
        <InputLabel shrink sx={{ position: 'relative', mb: 0.5, display: 'block' }}>
          {label}
        </InputLabel>
        <Tag
          label={`${t_i18n('Externally managed')} (${sourceLabel})`}
          color={theme.palette.primary.main}
        />
      </Box>
    );
  }

  return (
    <Box sx={style}>
      {isEditing ? (
        <>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 2,
              flexWrap: action === 'override' && multiline ? 'wrap' : 'nowrap',
            }}
          >
            <FormControl variant="standard" sx={{ minWidth: 160, flexShrink: 0 }}>
              <InputLabel shrink>{label}</InputLabel>
              <Select
                value={action}
                onChange={(e) => {
                  const v = e.target.value as SecretAction;
                  setFieldValue(`${namePrefix}_action`, v);
                  if (v !== 'override') {
                    setFieldValue(`${namePrefix}_new_value`, '');
                  }
                }}
                label={label}
              >
                <MenuItem value="keep">{t_i18n('Keep existing secret')}</MenuItem>
                <MenuItem value="override">{t_i18n('Set a new secret')}</MenuItem>
              </Select>
            </FormControl>
            {action === 'override' && (
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name={`${namePrefix}_new_value`}
                  label={t_i18n('New value (leave empty to remove)')}
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
          </Box>
        </>
      ) : (
        <>
          <InputLabel shrink sx={{ position: 'relative', mb: 0.5, display: 'block' }}>
            {label}
          </InputLabel>
          <Field
            component={TextField}
            variant="standard"
            name={`${namePrefix}_new_value`}
            label={t_i18n('Value')}
            fullWidth
            type="password"
            multiline={multiline}
            rows={multiline ? 4 : undefined}
          />
        </>
      )}
    </Box>
  );
};

export default SecretFieldControl;
