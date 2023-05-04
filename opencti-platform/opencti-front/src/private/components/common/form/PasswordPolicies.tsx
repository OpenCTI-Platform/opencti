import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { makeStyles } from '@mui/styles';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { useFormatter } from '../../../../components/i18n';
import { PasswordPolicies$key } from './__generated__/PasswordPolicies.graphql';
import useAuth from '../../../../utils/hooks/useAuth';

const useStyles = makeStyles(() => ({
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

const passwordPoliciesFragment = graphql`
  fragment PasswordPolicies on Settings {
    password_policy_min_length
    password_policy_max_length
    password_policy_min_symbols
    password_policy_min_numbers
    password_policy_min_words
    password_policy_min_lowercase
    password_policy_min_uppercase
  }
`;

const PasswordPolicies: FunctionComponent<{ style?: object }> = ({ style }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { settings } = useAuth();
  const {
    password_policy_min_length,
    password_policy_max_length,
    password_policy_min_symbols,
    password_policy_min_numbers,
    password_policy_min_words,
    password_policy_min_lowercase,
    password_policy_min_uppercase,
  } = useFragment<PasswordPolicies$key>(passwordPoliciesFragment, settings);
  // If no specific policies, just render empty element
  if (password_policy_min_length === 0 && password_policy_max_length === 0 && password_policy_min_symbols === 0 && password_policy_min_numbers === 0
      && password_policy_min_words === 0 && password_policy_min_lowercase === 0 && password_policy_min_uppercase === 0) {
    return <></>;
  }
  return <div style={style}>
    <Alert classes={{ root: classes.alert, message: classes.message }} severity="warning" variant="outlined" style={{ position: 'relative' }}>
      <AlertTitle>
        {t('Password security policies')}
      </AlertTitle>
      <div>
        {(password_policy_min_length ?? 0) > 0 && <div>{t('Number of chars must be greater or equals to')} {password_policy_min_length}</div>}
        {(password_policy_max_length ?? 0) > 0 && <div>{t('Number of chars must be lower or equals to')} {password_policy_max_length}</div>}
        {(password_policy_min_symbols ?? 0) > 0 && <div>{t('Number of symbols must be greater or equals to')} {password_policy_min_symbols}</div>}
        {(password_policy_min_numbers ?? 0) > 0 && <div>{t('Number of digits must be greater or equals to')} {password_policy_min_numbers}</div>}
        {(password_policy_min_words ?? 0) > 0 && <div>{t('Number of words (split on hyphen, space) must be greater or equals to')} {password_policy_min_words}</div>}
        {(password_policy_min_lowercase ?? 0) > 0 && <div>{t('Number of lowercase chars must be greater or equals to')} {password_policy_min_lowercase}</div>}
        {(password_policy_min_uppercase ?? 0) > 0 && <div>{t('Number of uppercase chars must be greater or equals to')} {password_policy_min_uppercase}</div>}
      </div>
    </Alert>
  </div>;
};

export default PasswordPolicies;
