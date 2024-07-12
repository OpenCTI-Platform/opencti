import { IconButton, IconButtonProps, Tooltip } from '@mui/material';
import { FormatSize } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from '../../i18n';

interface BulkTextModalButtonProps {
  onClick: IconButtonProps['onClick']
}

const BulkTextModalButton = ({ onClick }: BulkTextModalButtonProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Tooltip title={t_i18n('Create multiple entities')}>
      <IconButton
        color="primary"
        onClick={onClick}
        sx={{ marginLeft: 1 }}
      >
        <FormatSize />
      </IconButton>
    </Tooltip>
  );
};

export default BulkTextModalButton;
