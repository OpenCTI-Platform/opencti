import { useCookies } from 'react-cookie';
import LoginAlert from './LoginAlert';

const FLASH_COOKIE = 'opencti_flash';

const AlertFlashError = () => {
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  if (!flashError) return null;

  return (
    <LoginAlert severity="error">
      {flashError}
    </LoginAlert>
  );
};

export default AlertFlashError;
