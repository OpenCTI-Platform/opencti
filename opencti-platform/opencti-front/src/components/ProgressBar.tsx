import { Button, Dialog, DialogActions, DialogContent, DialogTitle, LinearProgress, Typography } from '@mui/material';
import React, { ReactNode } from 'react';
import { useFormatter } from './i18n';

interface ProgressBarProps {
  open: boolean
  value: number
  title: string
  label?: string
  onClose: () => void
  children?: ReactNode
}

const ProgressBar = ({
  open,
  value,
  title,
  label,
  onClose,
  children,
}: ProgressBarProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog open={open} fullWidth={true}>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <LinearProgress style={{ flex: 1 }} variant="buffer" value={value} valueBuffer={value + 10} />
          {label && <Typography style={{ flexShrink: 0 }}>{label}</Typography>}
        </div>
        {children}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ProgressBar;
