import { Tooltip } from '@mui/material';
import { CheckOutlined, CloseOutlined } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from '../../../../../components/i18n';

interface AttackPatternsMatrixShouldCoverIconProps {
  isOverlapping: boolean;
}

// Green tick when the security posture covers the technique, red cross when it
// does not. Rendered directly on the technique cell (no shield backing).
const AttackPatternsMatrixShouldCoverIcon = ({ isOverlapping }: AttackPatternsMatrixShouldCoverIconProps) => {
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
        ? <CheckOutlined fontSize="medium" color="success" />
        : <CloseOutlined fontSize="medium" color="error" />
      }
    </Tooltip>
  );
};

export default AttackPatternsMatrixShouldCoverIcon;
