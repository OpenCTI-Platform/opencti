import { Alert, AlertProps, AlertTitle } from '@mui/material';
import { useTheme } from '@mui/styles';
import { PropsWithChildren } from 'react';
import { Theme } from '../../../components/Theme';

interface LoginAlertProps extends PropsWithChildren {
  severity: AlertProps['severity'];
}

const LoginAlert = ({ children, severity }: LoginAlertProps) => {
  const theme = useTheme<Theme>();

  return (
    <Alert variant="outlined" severity={severity}>
      <AlertTitle
        fontSize={12}
        margin={0}
        color={theme.palette.text.light}
      >
        {children}
      </AlertTitle>
    </Alert>
  );
};

export default LoginAlert;
