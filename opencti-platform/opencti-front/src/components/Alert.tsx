import MuiAlert from '@mui/material/Alert';
import type { AlertProps as MuiAlertProps } from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import React, { CSSProperties, ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';

type AlertProps = {
  content: ReactNode;
  style?: CSSProperties;
  severity?: MuiAlertProps['severity'];
};

const Alert = ({ content, style, severity = 'info' }: AlertProps) => {
  const theme = useTheme<Theme>();

  return (
    <div style={style}>
      <MuiAlert
        severity={severity}
        variant="outlined"
        style={{ padding: `0 ${theme.spacing(1)}` }}
      >
        <Typography variant={'body2'}>{content}</Typography>
      </MuiAlert>
    </div>
  );
};

export default Alert;
