import { Box, Typography } from '@mui/material';
import AttackPatternsMatrixShouldCoverIcon from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixShouldCoverIcon';
import React from 'react';
import { FilteredAttackPattern, FilteredSubAttackPattern, MinimalAttackPattern } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import useHelper from '../../../../../utils/hooks/useHelper';

interface AttackPatternsMatrixColumnsElementProps {
  attackPattern: FilteredAttackPattern | FilteredSubAttackPattern;
  handleToggleHover: (id: string) => void;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  border: string;
  backgroundColor: string;
  attackPatternIdsToOverlap?: string[];
}

const AttackPatternsMatrixColumnsElement = ({
  attackPattern,
  handleToggleHover,
  handleOpen,
  border,
  backgroundColor,
  attackPatternIdsToOverlap,
}: AttackPatternsMatrixColumnsElementProps) => {
  const { isFeatureEnable } = useHelper();
  const isSecurityPlatformEnabled = isFeatureEnable('SECURITY_PLATFORM');
  return (
    <Box
      onMouseEnter={() => handleToggleHover(attackPattern.attack_pattern_id)}
      onMouseLeave={() => handleToggleHover(attackPattern.attack_pattern_id)}
      onClick={(e) => handleOpen(attackPattern, e)}
      sx={{
        display: 'flex',
        cursor: 'pointer',
        border,
        backgroundColor,
        padding: 1.25,
        justifyContent: 'space-between',
        gap: 1,
        alignItems: 'center',
        whiteSpace: 'normal',
        width: '100%',
      }}
    >
      <Typography variant="body2" fontSize={10}>
        {attackPattern.name}
      </Typography>
      {isSecurityPlatformEnabled && attackPatternIdsToOverlap?.length !== undefined && attackPattern.level > 0 && (
        <AttackPatternsMatrixShouldCoverIcon
          isOverlapping={attackPattern.isOverlapping || false}
        />
      )}
    </Box>
  );
};

export default AttackPatternsMatrixColumnsElement;
