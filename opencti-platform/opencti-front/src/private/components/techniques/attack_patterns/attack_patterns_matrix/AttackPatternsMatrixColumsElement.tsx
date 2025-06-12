import { Box, Typography } from '@mui/material';
import AttackPatternsMatrixShouldCoverIcon from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixShouldCoverIcon';
import React, { useState } from 'react';
import {
  FilteredAttackPattern,
  FilteredSubAttackPattern,
  getBoxStyles,
  MinimalAttackPattern,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import { useTheme } from '@mui/material/styles';
import useHelper from '../../../../../utils/hooks/useHelper';
import type { Theme } from '../../../../../components/Theme';

interface AttackPatternsMatrixColumnsElementProps {
  attackPattern: FilteredAttackPattern | FilteredSubAttackPattern;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  attackPatternIdsToOverlap?: string[];
  isSecurityPlatform: boolean;
}

const AttackPatternsMatrixColumnsElement = ({
  attackPattern,
  handleOpen,
  attackPatternIdsToOverlap,
  isSecurityPlatform,
}: AttackPatternsMatrixColumnsElementProps) => {
  const theme = useTheme<Theme>();
  const { isFeatureEnable } = useHelper();
  const isSecurityPlatformEnabled = isFeatureEnable('SECURITY_PLATFORM');
  const [isHovered, setIsHovered] = useState(false);

  const { border, backgroundColor } = getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });

  return (
    <Box
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
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
      {isSecurityPlatformEnabled && !isSecurityPlatform && attackPatternIdsToOverlap?.length !== undefined && attackPattern.isCovered && (
        <AttackPatternsMatrixShouldCoverIcon
          isOverlapping={attackPattern.isOverlapping || false}
        />
      )}
    </Box>
  );
};

export default AttackPatternsMatrixColumnsElement;
