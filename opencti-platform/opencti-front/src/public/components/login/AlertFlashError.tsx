import { useCookies } from 'react-cookie';
import { useFormatter } from '../../../components/i18n';
import LoginAlert from './LoginAlert';

const FLASH_COOKIE = 'opencti_flash';

export const FLASH_CODE_MESSAGES: Record<string, string> = {
  IP_NOT_ALLOWED: 'Your IP address is not allowed to access this platform',
  PASSWORD_CHANGE_REQUIRED: 'You must change your password before continuing',
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

  const displayMessage = FLASH_CODE_MESSAGES[flashError]
    ? t_i18n(FLASH_CODE_MESSAGES[flashError])
    : t_i18n(flashError); // Backward compatibility with raw messages

  return (
    <LoginAlert severity="error">
      {displayMessage}
    </LoginAlert>
  );
};

export default AlertFlashError;
