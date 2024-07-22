import { Button, ButtonProps } from '@mui/material';
import React from 'react';
import { useFormatter } from '../../i18n';

interface BulkTextModalButtonProps {
  onClick: ButtonProps['onClick']
  sx?: ButtonProps['sx']
  title?: string
}

const BulkTextModalButton = ({ onClick, title, sx = {} }: BulkTextModalButtonProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Button
      color="primary"
      variant="contained"
      onClick={onClick}
      sx={{ marginLeft: 'auto', marginRight: 2, ...sx }}
    >
      {title || t_i18n('Create multiple entities')}
    </Button>
  );
};

export default BulkTextModalButton;
