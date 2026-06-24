import React, { FunctionComponent } from 'react';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { CheckCircleOutlined, RadioButtonUnchecked } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from './i18n';

export interface PasswordPolicies {
  minLength?: number | null;
  maxLength?: number | null;
  minSymbols?: number | null;
  minNumbers?: number | null;
  minWords?: number | null;
  minLowercase?: number | null;
  minUppercase?: number | null;
}

interface PasswordPoliciesAlertProps {
  policies: PasswordPolicies;
  value?: string;
}

export const countSymbols = (s: string) => (s.match(/[^a-zA-Z0-9]/g) ?? []).length;
export const countDigits = (s: string) => (s.match(/[0-9]/g) ?? []).length;
export const countWords = (s: string) => s.split(/[\s-]+/).filter(Boolean).length;
export const countLowercase = (s: string) => (s.match(/[a-z]/g) ?? []).length;
export const countUppercase = (s: string) => (s.match(/[A-Z]/g) ?? []).length;

const PasswordPoliciesAlert: FunctionComponent<PasswordPoliciesAlertProps> = ({ policies, value }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { minLength, maxLength, minSymbols, minNumbers, minWords, minLowercase, minUppercase } = policies;
  const hasPolicy = (
    (minLength ?? 0) > 0
    || (maxLength ?? 0) > 0
    || (minSymbols ?? 0) > 0
    || (minNumbers ?? 0) > 0
    || (minWords ?? 0) > 0
    || (minLowercase ?? 0) > 0
    || (minUppercase ?? 0) > 0
  );

  if (!hasPolicy) return null;

  const isLive = value !== undefined;

  const checks = {
    minLength: !isLive || (value.length >= (minLength ?? 0)),
    maxLength: !isLive || (value.length <= (maxLength ?? Infinity)),
    minSymbols: !isLive || (countSymbols(value) >= (minSymbols ?? 0)),
    minNumbers: !isLive || (countDigits(value) >= (minNumbers ?? 0)),
    minWords: !isLive || (countWords(value) >= (minWords ?? 0)),
    minLowercase: !isLive || (countLowercase(value) >= (minLowercase ?? 0)),
    minUppercase: !isLive || (countUppercase(value) >= (minUppercase ?? 0)),
  };

  const PolicyLine = ({ met, label }: { met: boolean; label: string }) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {isLive
        ? met
          ? <CheckCircleOutlined fontSize="small" style={{ color: theme.palette.success.main }} />
          : <RadioButtonUnchecked fontSize="small" style={{ color: theme.palette.text.disabled }} />
        : null}
      <span style={{ color: isLive ? (met ? theme.palette.success.main : theme.palette.text.disabled) : 'inherit' }}>
        {label}
      </span>
    </div>
  );

  return (
    <Alert severity={isLive ? 'info' : 'warning'} variant="outlined">
      <AlertTitle>{t_i18n('Password security policies')}</AlertTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {(minLength ?? 0) > 0 && <PolicyLine met={checks.minLength} label={`${t_i18n('Number of chars must be greater or equals to')} ${minLength}`} />}
        {(maxLength ?? 0) > 0 && <PolicyLine met={checks.maxLength} label={`${t_i18n('Number of chars must be lower or equals to')} ${maxLength}`} />}
        {(minSymbols ?? 0) > 0 && <PolicyLine met={checks.minSymbols} label={`${t_i18n('Number of symbols must be greater or equals to')} ${minSymbols}`} />}
        {(minNumbers ?? 0) > 0 && <PolicyLine met={checks.minNumbers} label={`${t_i18n('Number of digits must be greater or equals to')} ${minNumbers}`} />}
        {(minWords ?? 0) > 0 && <PolicyLine met={checks.minWords} label={`${t_i18n('Number of words (split on hyphen, space) must be greater or equals to')} ${minWords}`} />}
        {(minLowercase ?? 0) > 0 && <PolicyLine met={checks.minLowercase} label={`${t_i18n('Number of lowercase chars must be greater or equals to')} ${minLowercase}`} />}
        {(minUppercase ?? 0) > 0 && <PolicyLine met={checks.minUppercase} label={`${t_i18n('Number of uppercase chars must be greater or equals to')} ${minUppercase}`} />}
      </div>
    </Alert>
  );
};

export default PasswordPoliciesAlert;
