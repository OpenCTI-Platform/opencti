import { Tooltip } from '@mui/material';
import { ShieldCheck, ShieldRemove } from 'mdi-material-ui';
import React from 'react';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

interface AttackPatternsMatrixShouldCoverIconProps {
  isOverlapping: boolean;
}

// Green shield with a check when the security posture covers the technique,
// red shield with a cross when it does not. The shield backing makes the
// tick/cross read clearly against the coloured matrix cells.
const AttackPatternsMatrixShouldCoverIcon = ({ isOverlapping }: AttackPatternsMatrixShouldCoverIconProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
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
        ? <ShieldCheck fontSize="medium" htmlColor={theme.palette.success.main} />
        : <ShieldRemove fontSize="medium" htmlColor={theme.palette.error.main} />
      }
    </Tooltip>
  );
};

export default AttackPatternsMatrixShouldCoverIcon;
