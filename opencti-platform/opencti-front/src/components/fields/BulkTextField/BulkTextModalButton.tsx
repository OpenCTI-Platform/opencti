import { ButtonProps, Tooltip, Box } from '@mui/material';
import Button from '@common/button/Button';
import React from 'react';
import { useFormatter } from '../../i18n';

interface BulkTextModalButtonProps {
  onClick: ButtonProps['onClick'];
  disabled?: ButtonProps['disabled'];
  sx?: ButtonProps['sx'];
  title?: string;
}

const BulkTextModalButton = ({ onClick, title, disabled, sx = {} }: BulkTextModalButtonProps) => {
  const { t_i18n } = useFormatter();

  const bulkButton = (
    <Box sx={{ marginLeft: 'auto', marginRight: 2, ...sx }}>
      <Button
        variant="tertiary"
        onClick={onClick}
        disabled={disabled}

      >
        {title || t_i18n('Create multiple entities')}
      </Button>
    </Box>
  );

  return disabled
    ? <Tooltip title={t_i18n('Bulk creation not supported for this type')}>{bulkButton}</Tooltip>
    : bulkButton;
};

export default BulkTextModalButton;
