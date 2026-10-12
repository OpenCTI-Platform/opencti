import React, { useState } from 'react';
import { Box, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import AttackPatternsMatrixShouldCoverIcon from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixShouldCoverIcon';
import {
  FilteredAttackPattern,
  FilteredSubAttackPattern,
  applyCellDecoration,
  getBoxStyles,
  MinimalAttackPattern,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import type { Theme } from '../../../../../components/Theme';
import { hexToRGB } from '../../../../../utils/Colors';
import SecurityCoverageScores from '../../../analyses/security_coverages/security_coverage_scores/SecurityCoverageScores';
import { CoverageInformation } from '@components/analyses/security_coverages/SecurityCoverage-types';
import { useFormatter } from '../../../../../components/i18n';
import { MatrixConfig } from './attackPatternsMatrixConfig';
import AttackPatternsMatrixCellTooltip from './AttackPatternsMatrixCellTooltip';
import type { CellDecoration } from '../../../workspaces/investigations/matrix/matrixTypes';

interface AttackPatternsMatrixColumnsElementProps {
  attackPattern: FilteredAttackPattern | FilteredSubAttackPattern;
  config: MatrixConfig;
  decoration?: CellDecoration;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  attackPatternIdsToOverlap?: string[];
  isSecurityPlatform: boolean;
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<CoverageInformation>>;
  entityId?: string;
}

const AttackPatternsMatrixColumnsElement = ({
  attackPattern,
  config,
  decoration,
  handleOpen,
  attackPatternIdsToOverlap,
  isSecurityPlatform,
  isCoverage = false,
  coverageMap,
}: AttackPatternsMatrixColumnsElementProps) => {
  const theme = useTheme<Theme>();
  const [isHovered, setIsHovered] = useState(false);
  const { t_i18n } = useFormatter();

  // Get coverage information if in coverage mode
  const coverage = isCoverage && coverageMap ? coverageMap.get(attackPattern.attack_pattern_id) : null;

  const getAvgCoverageScore = (): number | null => {
    if (coverage) {
      return coverage.reduce((sum, c) => sum + c.coverage_score, 0) / coverage.length;
    } else {
      return null;
    }
  };

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
    const avgScore = getAvgCoverageScore();

    // Calculate color based on score (0-100)
    // Green to red gradient
    let red = 255;
    let green = 255;
    if (avgScore) {
      red = Math.round(255 * (1 - avgScore / 100));
      green = Math.round(255 * (avgScore / 100));
    }
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
  const { border, borderColor, backgroundColor, labelColor } = applyCellDecoration(styles, decoration);

  const a11yProps = () => {
    if (decoration) {
      return { 'aria-label': decoration.accessibleName };
    }
    const scoreValue = getAvgCoverageScore();
    if (scoreValue) {
      return {
        'aria-label': `${Math.round(scoreValue)}% ${t_i18n('Coverage')}`,
      };
    }
    return undefined;
  };

  // In keyboard mode the cell is a real button, so it is focusable and opens its menu with Enter or Space.
  const buttonProps = config.keyboardCells
    ? { component: 'button' as const, type: 'button' as const }
    : {};
  const buttonResetSx = config.keyboardCells
    ? { font: 'inherit', color: 'inherit', textAlign: 'left', margin: 0, appearance: 'none' } as const
    : {};

  const cell = (
    <Box
      {...buttonProps}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={(e) => handleOpen(attackPattern, e)}
      {...a11yProps()}
      sx={{
        display: 'flex',
        cursor: 'pointer',
        border,
        borderColor,
        backgroundColor,
        padding: 1.25,
        justifyContent: 'space-between',
        gap: 1,
        alignItems: 'center',
        whiteSpace: 'normal',
        width: '100%',
        position: 'relative',
        ...buttonResetSx,
      }}
    >
      <Typography variant="body2" fontSize={10} color={labelColor} component={config.keyboardCells ? 'span' : 'p'}>
        {config.formatLabel(attackPattern)}
      </Typography>

      {isCoverage && attackPattern.isCovered && (
        <>
          <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <SecurityCoverageScores
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

  return <AttackPatternsMatrixCellTooltip decoration={decoration}>{cell}</AttackPatternsMatrixCellTooltip>;
};

export default AttackPatternsMatrixColumnsElement;
