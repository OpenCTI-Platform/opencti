import { useFormatter } from '../../../components/i18n';
import LoginAlert from './LoginAlert';
import { useLoginContext } from './loginContext';
import { ResetPwdStep } from './ResetPassword';

const AlertChangePwd = () => {
  const { t_i18n } = useFormatter();
  const {
    pwdChanged,
    resetPwdStep,
    changePasswordInError,
  } = useLoginContext();

  const inResetStep = resetPwdStep === ResetPwdStep.RESET_PASSWORD;
  const inLoginForm = resetPwdStep === undefined;

  if (!inResetStep && !(inLoginForm && pwdChanged)) return null;

  return (
    <>
      {inResetStep && (
        <>
          {changePasswordInError ? (
            <LoginAlert severity="error">
              {t_i18n('This new password does not comply with the platform policies.')}
            </LoginAlert>
          ) : (
            <LoginAlert severity="info">
              {t_i18n('You can now set a new password for your account.')}
            </LoginAlert>
          )}
        </>
      )}
      {inLoginForm && (
        <LoginAlert severity="success">
          {t_i18n('Your password has been updated.')}
        </LoginAlert>
      )}
    </>
  );
};

export default AlertChangePwd;
