import { Button, ButtonProps } from '@mui/material';
import React from 'react';
import { useFormatter } from '../../i18n';

interface BulkTextModalButtonProps {
  onClick: ButtonProps['onClick']
}

const BulkTextModalButton = ({ onClick }: BulkTextModalButtonProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Button
      color="primary"
      variant="contained"
      onClick={onClick}
      sx={{ marginLeft: 'auto', marginRight: 2 }}
    >
      {t_i18n('Create multiple entities')}
    </Button>
  );
};

export default BulkTextModalButton;
