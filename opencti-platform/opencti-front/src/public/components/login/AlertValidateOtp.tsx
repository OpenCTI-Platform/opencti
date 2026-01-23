import { useFormatter } from '../../../components/i18n';
import LoginAlert from './LoginAlert';
import { useLoginContext } from './loginContext';
import { ResetPwdStep } from './ResetPassword';

const AlertValidateOtp = () => {
  const { t_i18n } = useFormatter();
  const {
    resetPwdStep,
    validateOtpInError,
    resendCodeDisabled,
  } = useLoginContext();

  if (resetPwdStep !== ResetPwdStep.VALIDATE_OTP) return null;

  return (
    <>
      {validateOtpInError ? (
        <LoginAlert severity="error">
          {resendCodeDisabled
            ? t_i18n('The reset code you entered is invalid or has expired. You can request a new code after a delay of 30 seconds.')
            : t_i18n('The reset code you entered is invalid or has expired. You can request a new code.')
          }
        </LoginAlert>
      ) : (
        <LoginAlert severity="info">
          {t_i18n('If the email address you entered is associated with an account, you will receive a confirmation email with a reset code shortly.')}
        </LoginAlert>
      )}
    </>
  );
};

export default AlertValidateOtp;
