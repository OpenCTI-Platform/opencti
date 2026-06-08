import React, { FunctionComponent } from 'react';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
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
}

const PasswordPoliciesAlert: FunctionComponent<PasswordPoliciesAlertProps> = ({ policies }) => {
  const { t_i18n } = useFormatter();
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

  return (
    <Alert severity="warning" variant="outlined">
      <AlertTitle>{t_i18n('Password security policies')}</AlertTitle>
      <div>
        {(minLength ?? 0) > 0 && <div>{t_i18n('Number of chars must be greater or equals to')} {minLength}</div>}
        {(maxLength ?? 0) > 0 && <div>{t_i18n('Number of chars must be lower or equals to')} {maxLength}</div>}
        {(minSymbols ?? 0) > 0 && <div>{t_i18n('Number of symbols must be greater or equals to')} {minSymbols}</div>}
        {(minNumbers ?? 0) > 0 && <div>{t_i18n('Number of digits must be greater or equals to')} {minNumbers}</div>}
        {(minWords ?? 0) > 0 && <div>{t_i18n('Number of words (split on hyphen, space) must be greater or equals to')} {minWords}</div>}
        {(minLowercase ?? 0) > 0 && <div>{t_i18n('Number of lowercase chars must be greater or equals to')} {minLowercase}</div>}
        {(minUppercase ?? 0) > 0 && <div>{t_i18n('Number of uppercase chars must be greater or equals to')} {minUppercase}</div>}
      </div>
    </Alert>
  );
};

export default PasswordPoliciesAlert;
