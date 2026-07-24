import React, { useState } from 'react';
import { Box, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import {
  FilteredAttackPattern,
  FilteredSubAttackPattern,
  getBoxStyles,
  MinimalAttackPattern,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import type { Theme } from '../../../../../components/Theme';
import { hexToRGB } from '../../../../../utils/Colors';
import MatrixEntityMarkers, { MatrixCellEntity } from './MatrixEntityMarkers';
import MatrixCoverageIndicator, { CoverageInformation } from './MatrixCoverageIndicator';
import { getHeatmapColors, HeatmapScale } from './attackPatternsHeatmap';
import SecurityCoverageScores from '../../../analyses/security_coverages/SecurityCoverageScores';

interface AttackPatternsMatrixColumnsElementProps {
  attackPattern: FilteredAttackPattern | FilteredSubAttackPattern;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  attackPatternIdsToOverlap?: string[];
  isSecurityPlatform: boolean;
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<{ readonly coverage_name: string; readonly coverage_score: number }>>;
  entityId?: string;
  entityUsageMap?: Map<string, MatrixCellEntity[]>;
  coverageOverlayMap?: Map<string, CoverageInformation>;
  heatmapActive?: boolean;
  frequencyMap?: Map<string, number>;
  heatmapScale?: HeatmapScale;
}

const AttackPatternsMatrixColumnsElement = ({
  attackPattern,
  handleOpen,
  attackPatternIdsToOverlap,
  isSecurityPlatform,
  isCoverage = false,
  coverageMap,
  entityUsageMap,
  coverageOverlayMap,
  heatmapActive = false,
  frequencyMap,
  heatmapScale,
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
  let { border, backgroundColor } = styles;

  // Frequency heatmap (US.3): a scored technique/sub-technique is filled with
  // its mapped colour, overriding the default/coverage styling.
  const heatmapCount = frequencyMap?.get(attackPattern.attack_pattern_id) ?? 0;
  const isHeatmapFilled = heatmapActive && heatmapScale !== undefined && heatmapCount > 0;
  if (isHeatmapFilled && heatmapScale) {
    const colors = getHeatmapColors(heatmapCount, heatmapScale);
    border = `1px solid ${colors.border}`;
    backgroundColor = colors.background;
  }
  // The pastel fills are light, so switch the label to dark text for contrast.
  const heatmapTextColor = isHeatmapFilled ? 'rgba(0, 0, 0, 0.87)' : undefined;

  const cellEntities = entityUsageMap?.get(attackPattern.attack_pattern_id) ?? [];
  const cellCoverage = coverageOverlayMap?.get(attackPattern.attack_pattern_id) ?? [];
  // "Compare with security posture": show the tick/cross in the top-right corner
  // (alongside the coverage donuts) when comparison is active for a covered technique.
  const showOverlap = !isSecurityPlatform && !isCoverage
    && attackPatternIdsToOverlap?.length !== undefined
    && attackPattern.isCovered;
  const hasCorner = cellCoverage.length > 0 || showOverlap;
  return (
    <Box
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={(e) => handleOpen(attackPattern, e)}
      sx={{
        display: 'flex',
        flexDirection: 'column',
        cursor: 'pointer',
        border,
        backgroundColor,
        padding: 1.25,
        // Reserve space in the top-right corner for the coverage donut / overlap overlay.
        paddingRight: hasCorner ? 4.5 : 1.25,
        gap: 0.75,
        whiteSpace: 'normal',
        width: '100%',
        position: 'relative',
      }}
    >
      <MatrixCoverageIndicator
        coverageInformation={cellCoverage}
        entities={cellEntities}
        showOverlap={showOverlap}
        isOverlapping={attackPattern.isOverlapping || false}
      />
      <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1, alignItems: 'center' }}>
        <Typography variant="body2" fontSize={10} sx={{ color: heatmapTextColor }}>
          {attackPattern.x_mitre_id ? `${attackPattern.x_mitre_id} - ${attackPattern.name}` : attackPattern.name}
        </Typography>

        {isCoverage && attackPattern.isCovered && (
          <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <SecurityCoverageScores
              coverage_information={coverage || null}
              variant="matrix"
            />
          </Box>
        )}
      </Box>

      {cellEntities.length > 0 && (
        <MatrixEntityMarkers entities={cellEntities} />
      )}
    </Box>
  );
};

export default AttackPatternsMatrixColumnsElement;
