import { useCookies } from 'react-cookie';
import { useFormatter } from '../../../components/i18n';
import LoginAlert from './LoginAlert';

const FLASH_COOKIE = 'opencti_flash';

const FLASH_CODE_MESSAGES: Record<string, string> = {
  IP_NOT_ALLOWED: 'Your IP address is not allowed to access this platform',
  PROVIDER_NOT_AVAILABLE: 'Authentication provider is not available',
  ENTERPRISE_EDITION_REQUIRED: 'This feature requires an Enterprise Edition license',
  AUTH_ERROR: 'Invalid authentication, please ask your administrator',
};

const AlertFlashError = () => {
  const { t_i18n } = useFormatter();
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  if (!flashError) return null;

  const displayMessage = FLASH_CODE_MESSAGES[flashError] ?? flashError;

  return (
    <LoginAlert severity="error">
      {t_i18n(displayMessage)}
    </LoginAlert>
  );
};

export default AlertFlashError;
