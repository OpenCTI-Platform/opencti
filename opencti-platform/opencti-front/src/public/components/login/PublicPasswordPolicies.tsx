import React, { FunctionComponent } from 'react';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { useFormatter } from '../../../components/i18n';

interface PublicPasswordPoliciesProps {
  password_policy_min_length?: number | null;
  password_policy_max_length?: number | null;
  password_policy_min_symbols?: number | null;
  password_policy_min_numbers?: number | null;
  password_policy_min_words?: number | null;
  password_policy_min_lowercase?: number | null;
  password_policy_min_uppercase?: number | null;
}

const PublicPasswordPolicies: FunctionComponent<PublicPasswordPoliciesProps> = ({
  password_policy_min_length,
  password_policy_max_length,
  password_policy_min_symbols,
  password_policy_min_numbers,
  password_policy_min_words,
  password_policy_min_lowercase,
  password_policy_min_uppercase,
}) => {
  const { t_i18n } = useFormatter();

  const hasPolicy = (
    (password_policy_min_length ?? 0) > 0
    || (password_policy_max_length ?? 0) > 0
    || (password_policy_min_symbols ?? 0) > 0
    || (password_policy_min_numbers ?? 0) > 0
    || (password_policy_min_words ?? 0) > 0
    || (password_policy_min_lowercase ?? 0) > 0
    || (password_policy_min_uppercase ?? 0) > 0
  );

  if (!hasPolicy) return null;

  return (
    <Alert severity="warning" variant="outlined" sx={{ width: '100%', mt: 2 }}>
      <AlertTitle>{t_i18n('Password security policies')}</AlertTitle>
      <div>
        {(password_policy_min_length ?? 0) > 0 && <div>{t_i18n('Number of chars must be greater or equals to')} {password_policy_min_length}</div>}
        {(password_policy_max_length ?? 0) > 0 && <div>{t_i18n('Number of chars must be lower or equals to')} {password_policy_max_length}</div>}
        {(password_policy_min_symbols ?? 0) > 0 && <div>{t_i18n('Number of symbols must be greater or equals to')} {password_policy_min_symbols}</div>}
        {(password_policy_min_numbers ?? 0) > 0 && <div>{t_i18n('Number of digits must be greater or equals to')} {password_policy_min_numbers}</div>}
        {(password_policy_min_words ?? 0) > 0 && <div>{t_i18n('Number of words (split on hyphen, space) must be greater or equals to')} {password_policy_min_words}</div>}
        {(password_policy_min_lowercase ?? 0) > 0 && <div>{t_i18n('Number of lowercase chars must be greater or equals to')} {password_policy_min_lowercase}</div>}
        {(password_policy_min_uppercase ?? 0) > 0 && <div>{t_i18n('Number of uppercase chars must be greater or equals to')} {password_policy_min_uppercase}</div>}
      </div>
    </Alert>
  );
};

export default PublicPasswordPolicies;
