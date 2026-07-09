import { useCookies } from 'react-cookie';
import { useFormatter } from '../../../components/i18n';
import LoginAlert from './LoginAlert';

const FLASH_COOKIE = 'opencti_flash';

const AlertFlashError = () => {
  const { t_i18n } = useFormatter();
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  if (!flashError) return null;

  return (
    <LoginAlert severity="error">
      {t_i18n(flashError)}
    </LoginAlert>
  );
};

export default AlertFlashError;
