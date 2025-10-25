import React, { useState } from 'react';
import { Box, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import AttackPatternsMatrixShouldCoverIcon from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixShouldCoverIcon';
import {
  FilteredAttackPattern,
  FilteredSubAttackPattern,
  getBoxStyles,
  MinimalAttackPattern,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import type { Theme } from '../../../../../components/Theme';
import { hexToRGB } from '../../../../../utils/Colors';
import SecurityCoverageInformation from '../../../analyses/security_coverages/SecurityCoverageInformation';

interface AttackPatternsMatrixColumnsElementProps {
  attackPattern: FilteredAttackPattern | FilteredSubAttackPattern;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  attackPatternIdsToOverlap?: string[];
  isSecurityPlatform: boolean;
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<{ readonly coverage_name: string; readonly coverage_score: number; }>>;
  entityId?: string;
}

const AttackPatternsMatrixColumnsElement = ({
  attackPattern,
  handleOpen,
  attackPatternIdsToOverlap,
  isSecurityPlatform,
  isCoverage = false,
  coverageMap,
}: AttackPatternsMatrixColumnsElementProps) => {
  const theme = useTheme<Theme>();
  const [isHovered, setIsHovered] = useState(false);

  // Get coverage information if in coverage mode
  const coverage = isCoverage && coverageMap ? coverageMap.get(attackPattern.attack_pattern_id) : null;

  // Calculate colors based on coverage score for active/covered boxes
  const getCoverageColors = () => {
    if (!isCoverage || !attackPattern.isCovered) {
      // Use default box styles when not in coverage mode or not covered
      const defaultStyles = getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });
      return { backgroundColor: defaultStyles.backgroundColor, border: defaultStyles.border };
    }

    // Box is covered and we're in coverage mode
    if (!coverage || coverage.length === 0) {
      // No coverage data but box is covered - use blue for unknown
      const bgColor = isHovered
        ? hexToRGB(theme.palette.primary.main, 0.3)
        : hexToRGB(theme.palette.primary.main, 0.15);
      const borderColor = hexToRGB(theme.palette.primary.main, 0.5);
      return {
        backgroundColor: bgColor,
        border: `1px solid ${borderColor}`,
      };
    }

    // Get the average coverage score if there are multiple coverages
    const avgScore = coverage.reduce((sum, c) => sum + c.coverage_score, 0) / coverage.length;

    // Calculate color based on score (0-100)
    // Green to red gradient
    const red = Math.round(255 * (1 - avgScore / 100));
    const green = Math.round(255 * (avgScore / 100));
    const bgOpacity = isHovered ? 0.25 : 0.15;
    const borderOpacity = 0.5;

    return {
      backgroundColor: `rgba(${red}, ${green}, 0, ${bgOpacity})`,
      border: `1px solid rgba(${red}, ${green}, 0, ${borderOpacity})`,
    };
  };

  // Get styles based on coverage mode
  const styles = isCoverage
    ? getCoverageColors()
    : getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });
  const { border, backgroundColor } = styles;
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
        position: 'relative',
      }}
    >
      <Typography variant="body2" fontSize={10}>
        {attackPattern.name}
      </Typography>

      {isCoverage && attackPattern.isCovered && (
        <>
          <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <SecurityCoverageInformation
              coverage_information={coverage || null}
              variant="matrix"
            />
          </Box>
        </>
      )}

      {!isSecurityPlatform && attackPatternIdsToOverlap?.length !== undefined && attackPattern.isCovered && !isCoverage && (
        <AttackPatternsMatrixShouldCoverIcon
          isOverlapping={attackPattern.isOverlapping || false}
        />
      )}
    </Box>
  );
};

export default AttackPatternsMatrixColumnsElement;
