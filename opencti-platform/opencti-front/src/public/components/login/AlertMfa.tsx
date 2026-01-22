import { useFormatter } from '../../../components/i18n';
import LoginAlert from './LoginAlert';
import { useLoginContext } from './loginContext';
import { ResetPwdStep } from './ResetPassword';

interface AlertMfaProps {
  forceDisplay?: boolean;
}

const AlertMfa = ({ forceDisplay = false }: AlertMfaProps) => {
  const { t_i18n } = useFormatter();
  const {
    mfaInError,
    resetPwdStep,
  } = useLoginContext();

  if (!forceDisplay && (resetPwdStep !== ResetPwdStep.MFA)) {
    return null;
  }

  const alertSeverity = mfaInError ? 'error' : 'info';
  const alertMessage = mfaInError
    ? t_i18n('The code is not correct.')
    : t_i18n('You need to validate your two-factor authentication. Please type the code generated in your application');

  return (
    <LoginAlert severity={alertSeverity}>
      {alertMessage}
    </LoginAlert>
  );
};

export default AlertMfa;
