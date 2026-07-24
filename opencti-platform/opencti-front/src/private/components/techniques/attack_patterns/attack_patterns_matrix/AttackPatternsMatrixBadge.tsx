import React from 'react';
import { Badge } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { FilteredAttackPattern, FilteredSubAttackPattern } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import type { Theme } from '../../../../../components/Theme';

interface AttackPatternsMatrixBadgeProps {
  attackPattern: FilteredAttackPattern;
  color: string;
  textColor?: string;
  // When the cell shows a top-right corner indicator (security-posture shield
  // and/or coverage donuts), the sub-technique count badge is shifted left so
  // the two do not overlap.
  hasCornerIndicator?: boolean;
  children: React.ReactNode;
}

const AttackPatternsMatrixBadge = ({ attackPattern, color, textColor, hasCornerIndicator = false, children }: AttackPatternsMatrixBadgeProps) => {
  const theme = useTheme<Theme>();
  const attackPatternsCount = (attackPattern.isCovered ? 1 : 0)
    + (attackPattern.subAttackPatterns?.filter((sub: FilteredSubAttackPattern) => sub.isCovered).length || 0);

  return (
    <Badge
      key={attackPattern.attack_pattern_id}
      invisible={!attackPatternsCount}
      badgeContent={attackPattern.subAttackPatternsTotal && `${attackPatternsCount}/${attackPattern.subAttackPatternsTotal + 1}`} // We add 1 to count the parent
      overlap="rectangular"
      anchorOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      sx={{
        '& .MuiBadge-badge': {
          backgroundColor: color,
          color: textColor || theme.palette.common.black,
          height: '14px',
          minWidth: '14px',
          fontSize: '10px',
          paddingInline: '4px',
          // Shift the count badge left so it clears the shield / coverage donuts
          // pinned in the same top-right corner.
          right: hasCornerIndicator ? 24 : 0,
        },
      }}
    >
      {children}
    </Badge>
  );
};

export default AttackPatternsMatrixBadge;
