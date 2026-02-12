import Dialog from '@common/dialog/Dialog';
import React, { FunctionComponent } from 'react';

interface ProcessDialogProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}

const ProcessDialog: FunctionComponent<ProcessDialogProps> = ({
  open,
  title,
  onClose,
  children,
}) => {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      showCloseButton
    >
      {children}
    </Dialog>
  );
};

export default ProcessDialog;
