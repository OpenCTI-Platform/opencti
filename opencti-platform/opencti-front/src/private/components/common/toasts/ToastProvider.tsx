import React, { ReactNode, createContext, useContext, useMemo, useState } from 'react';
import { Snackbar, SnackbarContent, SnackbarOrigin } from '@mui/material';
import { makeStyles, useTheme } from '@mui/styles';
import { CheckCircleOutline, ErrorOutline } from '@mui/icons-material';
import { Theme } from 'src/components/Theme';

const useStyles = makeStyles(() => ({
  toastContent: {
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  },
}));

interface ToastState {
  anchorOrigin: SnackbarOrigin,
  open: boolean,
  success: boolean,
  message?: string,
}

export interface ToastType {
  showSuccessToast: (message: string) => void,
  showErrorToast: (message: string) => void,
}

const defaultContext: ToastType = {
  showSuccessToast: () => {},
  showErrorToast: () => {},
};
export const ToastContext = createContext<ToastType>(defaultContext);
export const useToast = () => useContext(ToastContext);

const ToastProvider = ({ children }: { children: ReactNode }) => {
  const theme = (useTheme() as Theme);
  const classes = useStyles();
  const anchorOrigin: SnackbarOrigin = { vertical: 'top', horizontal: 'center' };
  const [toastState, setToastState] = useState<ToastState>({
    anchorOrigin,
    open: false,
    success: true,
    message: undefined,
  });
  const showSuccessToast = (message: string) => {
    setToastState({
      ...toastState,
      open: true,
      success: true,
      message,
    });
  };
  const showErrorToast = (message: string) => {
    setToastState({
      ...toastState,
      open: true,
      success: false,
      message,
    });
  };
  const value = useMemo(() => ({
    showSuccessToast,
    showErrorToast,
  }), []);
  return (<ToastContext.Provider value={value}>
    {children}
    <Snackbar
      anchorOrigin={toastState.anchorOrigin}
      open={toastState.open}
      onClose={() => setToastState({
        ...toastState,
        open: false,
      })}
      autoHideDuration={5000}
      key={'ToastProvider'}
    >
      <SnackbarContent
        sx={{
          backgroundColor: toastState.success
            ? theme?.palette?.success?.main ?? 'green'
            : theme?.palette?.error?.main ?? 'red',
        }}
        message={<div className={classes.toastContent}>
          {toastState.success
            ? <CheckCircleOutline />
            : <ErrorOutline />
          }
          {toastState.message}
        </div>}
      />
    </Snackbar>
  </ToastContext.Provider>
  );
};

export default ToastProvider;
