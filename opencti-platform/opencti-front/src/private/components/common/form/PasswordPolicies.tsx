import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { PasswordPolicies$key } from './__generated__/PasswordPolicies.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import PasswordPoliciesAlert from '../../../../components/PasswordPoliciesAlert';

const passwordPoliciesFragment = graphql`
  fragment PasswordPolicies on Settings {
    password_policy_min_length
    password_policy_max_length
    password_policy_min_symbols
    password_policy_min_numbers
    password_policy_min_words
    password_policy_min_lowercase
    password_policy_min_uppercase
    password_policy_history_count
  }
`;

interface PasswordPoliciesProps {
  value?: string;
  // 'admin' when the password is set for another user
  audience?: 'self' | 'admin';
  // A new account has no previous password to compare with
  hideHistory?: boolean;
}

const PasswordPolicies: FunctionComponent<PasswordPoliciesProps> = ({ value, audience = 'self', hideHistory = false }) => {
  const { settings } = useAuth();
  const {
    password_policy_min_length,
    password_policy_max_length,
    password_policy_min_symbols,
    password_policy_min_numbers,
    password_policy_min_words,
    password_policy_min_lowercase,
    password_policy_min_uppercase,
    password_policy_history_count,
  } = useFragment<PasswordPolicies$key>(passwordPoliciesFragment, settings);

  return (
    <PasswordPoliciesAlert
      policies={{
        minLength: password_policy_min_length,
        maxLength: password_policy_max_length,
        minSymbols: password_policy_min_symbols,
        minNumbers: password_policy_min_numbers,
        minWords: password_policy_min_words,
        minLowercase: password_policy_min_lowercase,
        minUppercase: password_policy_min_uppercase,
        historyCount: hideHistory ? 0 : password_policy_history_count,
      }}
      value={value}
      audience={audience}
    />
  );
};

export default PasswordPolicies;
