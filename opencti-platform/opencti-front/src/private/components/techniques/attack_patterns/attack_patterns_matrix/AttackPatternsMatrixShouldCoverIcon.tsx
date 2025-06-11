import { Tooltip } from '@mui/material';
import { CheckOutlined, CloseOutlined } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from '../../../../../components/i18n';

interface AttackPatternsMatrixShouldCoverIconProps {
  isOverlapping: boolean;
}

const AttackPatternsMatrixShouldCoverIcon = ({ isOverlapping }: AttackPatternsMatrixShouldCoverIconProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Tooltip
      title={t_i18n('Should cover')}
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
