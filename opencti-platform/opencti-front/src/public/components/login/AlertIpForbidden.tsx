import LoginAlert from './LoginAlert';
import { useFormatter } from '../../../components/i18n';

interface AlertIpForbiddenProps {
  show?: boolean;
}

const AlertIpForbidden = ({ show }: AlertIpForbiddenProps) => {
  const { t_i18n } = useFormatter();

  // Check URL param as fallback (e.g. direct redirect)
  const url = new URL(window.location.href);
  const fromUrl = url.searchParams.get('IpForbidden') === '1';

  if (!show && !fromUrl) return null;

  return (
    <LoginAlert severity="error">
      {t_i18n('Your IP address is not allowed to access this platform.')}
    </LoginAlert>
  );
};

export default AlertIpForbidden;

