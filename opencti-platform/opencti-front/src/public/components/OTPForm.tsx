import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../components/i18n';
import type { Theme } from '../../components/Theme';
import OtpInputField, { OTP_CODE_SIZE } from './OtpInputField';
import useApiMutation from '../../utils/hooks/useApiMutation';
import { useTheme } from '@mui/styles';

interface OTPFormProps {
  variant?: 'login' | 'resetPassword',
  email?: string,
  onCompleted?: () => void
}

const otpMutation = graphql`
  mutation OTPFormMutation($input: UserOTPLoginInput) {
    otpLogin(input: $input)
  }
`;

const logoutMutation = graphql`
  mutation OTPFormLogoutMutation {
    logout
  }
`;

const ResetPassword2faMutation = graphql`
  mutation OTPFormResetPasswordOtpLoginMutation($input: Verify2faInput!) {
    verify2fa(input: $input)
  }
`;

const OTPForm: FunctionComponent<OTPFormProps> = ({ variant = 'login', email, onCompleted }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data: string) => setCode(data);
  const [commitLogoutMutation] = useApiMutation(logoutMutation);
  const [commitOtpMutation] = useApiMutation(variant === 'login' ? otpMutation : ResetPassword2faMutation);
  const handleLogout = () => {
    commitLogoutMutation({
      variables: {},
      onCompleted: () => window.location.reload(),
    });
  };
  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commitOtpMutation({
      variables: {
        input: variant === 'login' ? { code } : { code, email },
      },
      onError: () => {
        setInputDisable(false);
        setCode('');
        setError(t_i18n('The code is not correct'));
      },
      onCompleted: () => {
        if (onCompleted) {
          onCompleted();
        } else {
          window.location.reload();
        }
      },
    });
  }
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: theme.spacing(3),
    }}>
      {error ? (
        <Alert
          severity="error"
          variant="outlined"
          style={{ alignSelf: 'stretch' }}
        >
          {error}
        </Alert>
      ) : (
        <Alert
          severity="info"
          variant="outlined"
          style={{ alignSelf: 'stretch' }}
        >
          {t_i18n('You need to validate your two-factor authentication. Please type the code generated in your application')}
        </Alert>
      )}
      <OtpInputField
        value={code}
        onChange={handleChange}
        isDisabled={inputDisable}
      />
      {variant === 'login' && (
        <Button
          type="submit"
          variant="contained"
          color="primary"
          onClick={handleLogout}
        >
          {t_i18n('Cancel')}
        </Button>
      )}
    </div>
  );
};

export default OTPForm;
