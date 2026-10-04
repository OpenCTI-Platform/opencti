import React, { type ReactNode } from 'react';
import Alert, { type AlertColor } from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';

interface SourceIntelligenceAlertProps {
  severity: AlertColor;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
}

// The design system release pinned by the platform ships no Alert: MUI stays the fallback until it does
const SourceIntelligenceAlert = ({ severity, title, description, action }: SourceIntelligenceAlertProps) => (
  <Alert severity={severity} variant="outlined" action={action}>
    <AlertTitle sx={{ marginBottom: description ? 0.5 : 0 }}>{title}</AlertTitle>
    {description}
  </Alert>
);

export default SourceIntelligenceAlert;
