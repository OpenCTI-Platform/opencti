import React from 'react';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import PasswordPoliciesAlert, { PasswordPolicies } from '../../../components/PasswordPoliciesAlert';
import { useLoginContext } from './loginContext';
import ForcePasswordChangeForm from '../../../components/ForcePasswordChangeForm';

interface ForcePasswordChangeProps {
  policies: PasswordPolicies;
}

const ForcePasswordChange = ({ policies }: ForcePasswordChangeProps) => {
  const { t_i18n } = useFormatter();
  const { setValue } = useLoginContext();

  const hasPasswordPolicies = Object.values(policies).some((value) => (value ?? 0) > 0);

  const backToLogin = () => {
    setValue('forcePasswordChange', false);
    setValue('resetPwdStep', undefined);
  };

  const handleSuccess = () => {
    window.location.reload();
  };

  const policiesRenderer = hasPasswordPolicies
    ? (password: string) => (
        <Box sx={{ width: '100%', mt: 2 }}>
          <PasswordPoliciesAlert policies={policies} value={password} />
        </Box>
      )
    : undefined;

  return (
    <ForcePasswordChangeForm
      onSuccess={handleSuccess}
      submitLabel={t_i18n('Update')}
      secondaryAction={(
        <Button
          variant="tertiary"
          onClick={backToLogin}
          sx={{ ml: -2 }}
        >
          {t_i18n('Back to login')}
        </Button>
      )}
      renderPolicies={policiesRenderer}
    />
  );
};

export default ForcePasswordChange;
