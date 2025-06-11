import React from 'react';
import { Badge } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { FilteredAttackPattern } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import type { Theme } from '../../../../../components/Theme';

interface AttackPatternsMatrixBadgeProps {
  attackPattern: FilteredAttackPattern;
  color: string;
  children: React.ReactNode;
}

const AttackPatternsMatrixBadge = ({ attackPattern, color, children }: AttackPatternsMatrixBadgeProps) => {
  const theme = useTheme<Theme>();
  return (
    <Badge
      key={attackPattern.attack_pattern_id}
      invisible={!attackPattern.level}
      badgeContent={attackPattern.subAttackPatternsTotal && `${attackPattern.level}/${attackPattern.subAttackPatternsTotal + 1}`} // We add 1 to count the parent
      overlap="rectangular"
      anchorOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      sx={{
        '& .MuiBadge-badge': {
          backgroundColor: color,
          color: theme.palette.common.black,
          height: '14px',
          minWidth: '14px',
          fontSize: '10px',
          paddingInline: '4px',
        },
      }}
    >
      {children}
    </Badge>
  );
};

export default AttackPatternsMatrixBadge;
