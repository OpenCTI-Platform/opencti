import React, { FunctionComponent, useContext } from 'react';
import { graphql, useFragment } from 'react-relay';
import { makeStyles } from '@mui/styles';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { useFormatter } from '../../../../components/i18n';
import { PasswordPolicies_policies$key } from './__generated__/PasswordPolicies_policies.graphql';
import { UserContext } from '../../../../utils/hooks/useAuth';

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
  fragment PasswordPolicies_policies on Settings {
    password_policy_min_length
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
  const settings = useContext(UserContext).settings as unknown as PasswordPolicies_policies$key;
  const policies = useFragment(passwordPoliciesFragment, settings);
  const { password_policy_min_length, password_policy_min_symbols, password_policy_min_numbers } = policies;
  const { password_policy_min_words, password_policy_min_lowercase, password_policy_min_uppercase } = policies;
  if (password_policy_min_length === 0 && password_policy_min_symbols === 0 && password_policy_min_numbers === 0
      && password_policy_min_words === 0 && password_policy_min_lowercase === 0 && password_policy_min_uppercase === 0) {
    return <></>;
  }
  return <div style={style}>
    <Alert classes={{ root: classes.alert, message: classes.message }} severity="warning" variant="outlined" style={{ position: 'relative' }}>
      <AlertTitle>
        {t('Password security policies')}
      </AlertTitle>
      <div>
        {(policies.password_policy_min_length ?? 0) > 0 && <div>{t('Number of chars must be greater or equals to')} {policies.password_policy_min_length}</div>}
        {(policies.password_policy_min_symbols ?? 0) > 0 && <div>{t('Number of symbols must be greater or equals to')} {policies.password_policy_min_symbols}</div>}
        {(policies.password_policy_min_numbers ?? 0) > 0 && <div>{t('Number of digits must be greater or equals to')} {policies.password_policy_min_numbers}</div>}
        {(policies.password_policy_min_words ?? 0) > 0 && <div>{t('Number of words (split on hyphen, space) must be greater or equals to')} {policies.password_policy_min_words}</div>}
        {(policies.password_policy_min_lowercase ?? 0) > 0 && <div>{t('Number of lowercase chars must be greater or equals to')} {policies.password_policy_min_lowercase}</div>}
        {(policies.password_policy_min_uppercase ?? 0) > 0 && <div>{t('Number of uppercase chars must be greater or equals to')} {policies.password_policy_min_uppercase}</div>}
      </div>
    </Alert>
  </div>;
};

export default PasswordPolicies;
