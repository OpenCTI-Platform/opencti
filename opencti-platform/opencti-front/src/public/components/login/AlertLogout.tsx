import { Alert, AlertTitle } from '@mui/material';
import { useState } from 'react';

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
    <Alert variant="outlined" severity="warning">
      <AlertTitle>You were automatically logged out due to session expiration.</AlertTitle>
    </Alert>
  );
};

export default AlertLogout;
