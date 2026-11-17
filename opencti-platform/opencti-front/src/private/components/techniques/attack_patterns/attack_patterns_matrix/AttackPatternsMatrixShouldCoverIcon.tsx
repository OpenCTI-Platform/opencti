import { Tooltip } from '@mui/material';
import { CheckOutlined, CloseOutlined } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from '../../../../../components/i18n';

interface AttackPatternsMatrixShouldCoverIconProps {
  isOverlapping: boolean;
  // Overrides the success/error colour, e.g. to stay readable on a heat-filled cell.
  color?: string;
}

const AttackPatternsMatrixShouldCoverIcon = ({ isOverlapping, color }: AttackPatternsMatrixShouldCoverIconProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Tooltip
      title={isOverlapping ? t_i18n('Security posture should cover the threat') : t_i18n('Security posture does not cover the threat')}
      sx={{
        display: 'flex',
        alignItems: 'center',
        height: 19,
      }}
    >
      {isOverlapping
        ? <CheckOutlined fontSize="medium" color={color ? undefined : 'success'} sx={color ? { color } : undefined} />
        : <CloseOutlined fontSize="medium" color={color ? undefined : 'error'} sx={color ? { color } : undefined} />
      }
    </Tooltip>
  );
};

export default AttackPatternsMatrixShouldCoverIcon;
