import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, LinearProgress, Typography } from '@mui/material';
import { ReactNode, useContext } from 'react';
import { useFormatter } from './i18n';
import { CreationFeedbackContext } from '../utils/hooks/useCreationFeedback';

interface ProgressBarProps {
  open: boolean;
  value: number;
  title: string;
  label?: string;
  variant?: 'determinate' | 'indeterminate' | 'buffer' | 'query';
  onClose: () => void;
  children?: ReactNode;
}

const ProgressBar = ({
  open,
  value,
  title,
  label,
  onClose,
  children,
  variant = 'buffer',
}: ProgressBarProps) => {
  const { t_i18n } = useFormatter();
  // After a bulk creation, the created objects may still be added to the surrounding container
  const { bulkCreation } = useContext(CreationFeedbackContext);

  return (
    <Dialog
      open={open}
      title={title}
    >
      <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
        <LinearProgress style={{ flex: 1 }} variant={variant} value={value} valueBuffer={value + 10} />
        {label && <Typography style={{ flexShrink: 0 }}>{label}</Typography>}
      </div>
      {children}
      <DialogActions>
        <Button onClick={onClose} disabled={!!bulkCreation?.progress?.inProgress}>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ProgressBar;
