import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../components/i18n';
import type { Theme } from '../../components/Theme';
import OtpInputField, { OTP_CODE_SIZE } from './OtpInputField';
import useApiMutation from '../../utils/hooks/useApiMutation';
import { APP_BASE_PATH } from '../../relay/environment';

interface OTPFormProps {
  variant?: 'login' | 'resetPassword',
  transactionId?: string,
  onCompleted?: () => void
}

const otpMutation = graphql`
  mutation OTPFormMutation($input: UserOTPLoginInput) {
    otpLogin(input: $input)
  }
`;

const ResetPasswordMfaMutation = graphql`
  mutation OTPFormResetPasswordOtpLoginMutation($input: VerifyMfaInput!) {
    verifyMfa(input: $input)
  }
`;

const OTPForm: FunctionComponent<OTPFormProps> = ({ variant = 'login', transactionId, onCompleted }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data: string) => setCode(data);
  const [commitOtpMutation] = useApiMutation(variant === 'login' ? otpMutation : ResetPasswordMfaMutation);
  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commitOtpMutation({
      variables: {
        input: variant === 'login' ? { code } : { code, transactionId },
      },
      onError: () => {
        setInputDisable(false);
        setCode('');
        setError(t_i18n('The code is not correct.'));
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
    }}
    >
      {error ? (
        <Alert severity="error" variant="outlined" style={{ alignSelf: 'stretch', textAlign: 'justify' }}>
          {error}
        </Alert>
      ) : (
        <Alert severity="info" variant="outlined" style={{ alignSelf: 'stretch', textAlign: 'justify' }}>
          {t_i18n('You need to validate your two-factor authentication. Please type the code generated in your application')}
        </Alert>
      )}
      <OtpInputField
        value={code}
        onChange={handleChange}
        isDisabled={inputDisable}
      />
      {variant === 'login' && (
        <a
          href={`${APP_BASE_PATH}/logout`}
          rel="noreferrer"
        >
          {t_i18n('Back to login')}
        </a>
      )}
    </div>
  );
};

export default OTPForm;
