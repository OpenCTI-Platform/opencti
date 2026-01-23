import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import OtpInputField, { OTP_CODE_SIZE } from './OtpInputField';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useLoginContext } from './loginContext';

interface OtpValidationProps {
  variant?: 'login' | 'resetPassword';
  transactionId?: string;
  onCompleted?: () => void;
}

const otpMutation = graphql`
  mutation OtpValidationMutation($input: UserOTPLoginInput) {
    otpLogin(input: $input)
  }
`;

const resetPasswordMfaMutation = graphql`
  mutation OtpValidationResetPasswordOtpLoginMutation($input: VerifyMfaInput!) {
    verifyMfa(input: $input)
  }
`;

const OtpValidation: FunctionComponent<OtpValidationProps> = ({
  variant = 'login',
  transactionId,
  onCompleted,
}) => {
  const { setValue } = useLoginContext();
  const [code, setCode] = useState('');
  const [inputDisable, setInputDisable] = useState(false);

  const [commitOtpMutation] = useApiMutation(
    variant === 'login' ? otpMutation : resetPasswordMfaMutation,
  );

  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commitOtpMutation({
      variables: {
        input: variant === 'login' ? { code } : { code, transactionId },
      },
      onError: () => {
        setInputDisable(false);
        setCode('');
        setValue('mfaInError', true);
      },
      onCompleted: () => {
        setValue('mfaInError', undefined);
        if (onCompleted) {
          onCompleted();
        } else {
          window.location.reload();
        }
      },
    });
  }

  return (
    <OtpInputField
      value={code}
      onChange={setCode}
      isDisabled={inputDisable}
    />
  );
};

export default OtpValidation;
