import { useTheme } from '@mui/material/styles';
import React, { useState } from 'react';
import MuiAccordion from '@mui/material/Accordion';
import MuiAccordionSummary from '@mui/material/AccordionSummary';
import IconButton from '@common/button/IconButton';
import ArrowForwardIosSharpIcon from '@mui/icons-material/ArrowForwardIosSharp';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Box } from '@mui/material';
import {
  FilteredAttackPattern,
  FilteredSubAttackPattern,
  getBoxStyles,
  isSubAttackPatternCovered,
  MinimalAttackPattern,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import AttackPatternsMatrixColumnsElement from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumsElement';
import AttackPatternsMatrixShouldCoverIcon from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixShouldCoverIcon';
import SecurityCoverageInformation from '../../../analyses/security_coverages/SecurityCoverageInformation';
import { hexToRGB } from '../../../../../utils/Colors';
import type { Theme } from '../../../../../components/Theme';

interface AccordionAttackPatternProps {
  attackPattern: FilteredAttackPattern;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  attackPatternIdsToOverlap?: string[];
  isSecurityPlatform: boolean;
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<{ readonly coverage_name: string; readonly coverage_score: number }>>;
  entityId?: string;
}

const AccordionAttackPattern = ({
  attackPattern,
  handleOpen,
  attackPatternIdsToOverlap,
  isSecurityPlatform,
  isCoverage = false,
  coverageMap,
  entityId,
}: AccordionAttackPatternProps) => {
  const theme = useTheme<Theme>();
  const [expanded, setExpanded] = useState(false);
  const [isHovered, setIsHovered] = useState(false);

  // Get coverage information if in coverage mode
  const coverage = isCoverage && coverageMap ? coverageMap.get(attackPattern.attack_pattern_id) : null;

  // Calculate colors based on coverage score for active/covered boxes
  const getCoverageColors = () => {
    if (!isCoverage) {
      // Use default box styles when not in coverage mode
      const defaultStyles = getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });
      return { backgroundColor: defaultStyles.backgroundColor, border: defaultStyles.border };
    }

    // Check if parent or any sub-technique is covered
    const hasAnyCoveredSubTechniques = attackPattern.subAttackPatterns?.some((sub) => (sub as FilteredSubAttackPattern).isCovered);

    if (!attackPattern.isCovered && !hasAnyCoveredSubTechniques) {
      // Neither parent nor sub-techniques are covered - use default styles
      const defaultStyles = getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });
      return { backgroundColor: defaultStyles.backgroundColor, border: defaultStyles.border };
    }

    // Calculate coverage including sub-techniques
    const parentCoverage = attackPattern.isCovered ? coverage : null;
    const subCoverages = attackPattern.subAttackPatterns
      ?.filter((sub) => (sub as FilteredSubAttackPattern).isCovered)
      ?.map((sub) => coverageMap?.get((sub as FilteredSubAttackPattern).attack_pattern_id))
      .filter(Boolean)
      .flat() || [];

    const allCoverages = [...(parentCoverage || []), ...subCoverages];

    // Box is covered and we're in coverage mode
    if (allCoverages.length === 0) {
      // No coverage data but box is covered - use blue for unknown
      const bgColor = isHovered
        ? hexToRGB(theme.palette.primary.main, 0.3)
        : hexToRGB(theme.palette.primary.main, 0.15);
      const borderColor = theme.palette.primary.main;
      return {
        backgroundColor: bgColor,
        border: `1px solid ${borderColor}`,
      };
    }

    // Get the average coverage score from all coverages (parent + sub-techniques)
    const avgScore = allCoverages.reduce((sum, c) => sum + (c?.coverage_score || 0), 0) / allCoverages.length;

    // Calculate color based on score (0-100)
    // Green to red gradient
    const red = Math.round(255 * (1 - avgScore / 100));
    const green = Math.round(255 * (avgScore / 100));
    const bgOpacity = isHovered ? 0.25 : 0.15;

    return {
      backgroundColor: `rgba(${red}, ${green}, 0, ${bgOpacity})`,
      border: `1px solid rgb(${red}, ${green}, 0)`,
    };
  };

  // Get styles based on coverage mode
  const styles = isCoverage
    ? getCoverageColors()
    : getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });
  const { border, backgroundColor } = styles;

  return (
    <MuiAccordion
      expanded={expanded}
      square
      disableGutters
      elevation={0}
      id={attackPattern.attack_pattern_id}
      key={attackPattern.attack_pattern_id}
      slotProps={{ transition: { unmountOnExit: true } }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      sx={{
        width: '100%',
        border,
        backgroundColor: 'transparent',
        '&:before': {
          display: 'none',
        },
      }}
    >
      <MuiAccordionSummary
        onClick={(e) => handleOpen(attackPattern, e)}
        expandIcon={(
          <IconButton onClick={(event) => {
            event.stopPropagation();
            setExpanded(!expanded);
          }}
          >
            <ArrowForwardIosSharpIcon sx={{
              fontSize: '0.9rem',
            }}
            />
          </IconButton>
        )}
        sx={{
          minHeight: 0,
          paddingLeft: 0,
          paddingRight: 1.25,
          backgroundColor,
          whiteSpace: 'wrap',
          flexDirection: 'row-reverse',
          '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
            transform: 'rotate(90deg)',
          },
          '.MuiAccordionSummary-content': { justifyContent: 'space-between', marginBlock: 1.25, alignItems: 'center' },
        }}
      >
        <Typography variant="body2" fontSize={10}>
          {attackPattern.name}
        </Typography>

        {isCoverage && attackPattern.isCovered && (
          <Box sx={{ marginLeft: 'auto' }}>
            <SecurityCoverageInformation
              coverage_information={coverage || null}
              variant="matrix"
            />
          </Box>
        )}

        {!isCoverage && attackPatternIdsToOverlap?.length !== undefined
          && (attackPattern.isCovered || isSubAttackPatternCovered(attackPattern as FilteredAttackPattern))
          && (
            <AttackPatternsMatrixShouldCoverIcon
              isOverlapping={attackPattern.isOverlapping || false}
            />
          )}
      </MuiAccordionSummary>
      <AccordionDetails
        sx={{
          padding: `0 0 0 ${theme.spacing(2)}`,
          borderTop: isCoverage && attackPattern.isCovered ? styles.border : border,
        }}
      >
        {attackPattern.subAttackPatterns?.map((subAttackPattern: FilteredSubAttackPattern) => {
          return (
            <AttackPatternsMatrixColumnsElement
              key={subAttackPattern.attack_pattern_id}
              attackPattern={subAttackPattern}
              handleOpen={handleOpen}
              attackPatternIdsToOverlap={attackPatternIdsToOverlap}
              isSecurityPlatform={isSecurityPlatform}
              isCoverage={isCoverage}
              coverageMap={coverageMap}
              entityId={entityId}
            />
          );
        })}
      </AccordionDetails>
    </MuiAccordion>
  );
};

export default AccordionAttackPattern;
