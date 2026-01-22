import { useState } from 'react';
import LoginAlert from './LoginAlert';

const AlertLogout = () => {
  // Session expiration automatic logout functions
  const [expired, setExpired] = useState(false);
  const handleExpiredChange = () => {
    if (expired === true) return; // Don't render again.
    setExpired(true);
  };

  const sessionExpiredUrlKeys = () => {
    const url = new URL(window.location.href);
    const key = url.searchParams.get('ExpiredSession');
    if (key === '1') handleExpiredChange();
  };
  sessionExpiredUrlKeys();

  if (expired !== true) return null;

  return (
    <LoginAlert severity="warning">
      You were automatically logged out due to session expiration.
    </LoginAlert>
  );
};

export default AlertLogout;
