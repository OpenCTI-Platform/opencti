import React from 'react';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { useFormatter } from './i18n';

const ErrorNotFound = () => {
  const { t_i18n } = useFormatter();
  return (
    <Alert severity="info">
      <AlertTitle>{t_i18n('Error')}</AlertTitle>
      {t_i18n('This page is not found on this OpenCTI application.')}
    </Alert>
  );
};

export default ErrorNotFound;
