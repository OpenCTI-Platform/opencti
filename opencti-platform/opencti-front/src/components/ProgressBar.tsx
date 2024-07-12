import { Button, Dialog, DialogActions, DialogContent, DialogTitle, LinearProgress, Typography } from '@mui/material';
import React, { ReactNode, useEffect, useState } from 'react';
import { useFormatter } from './i18n';

interface ProgressBarProps {
  open: boolean
  value: number
  title: string
  label?: string
  autoClose?: boolean
  onClose?: () => void
  children?: ReactNode
}

const ProgressBar = ({
  open,
  value,
  title,
  label,
  autoClose = false,
  onClose,
  children,
}: ProgressBarProps) => {
  const { t_i18n } = useFormatter();
  const [dialogOpen, setDialogOpen] = useState<boolean>(false);

  const close = () => {
    setDialogOpen(false);
    onClose?.();
  };

  useEffect(() => {
    if (open) setDialogOpen(true);
    if (!open && autoClose && dialogOpen) close();
  }, [open, dialogOpen, setDialogOpen]);

  return (
    <Dialog open={dialogOpen} fullWidth={true}>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <LinearProgress style={{ flex: 1 }} variant="buffer" value={value} valueBuffer={value + 10} />
          {label && <Typography style={{ flexShrink: 0 }}>{label}</Typography>}
        </div>
        {children}
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ProgressBar;
