import { Alert, AlertTitle } from '@mui/material';
import { useCookies } from 'react-cookie';

const FLASH_COOKIE = 'opencti_flash';

const AlertFlashError = () => {
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  if (!flashError) return null;

  return (
    <Alert variant="outlined" severity="error">
      <AlertTitle>{flashError}</AlertTitle>
    </Alert>
  );
};

export default AlertFlashError;
