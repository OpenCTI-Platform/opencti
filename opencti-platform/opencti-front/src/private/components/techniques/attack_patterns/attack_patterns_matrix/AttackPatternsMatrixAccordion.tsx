import { useTheme } from '@mui/material/styles';
import React, { useState } from 'react';
import MuiAccordion from '@mui/material/Accordion';
import MuiAccordionSummary from '@mui/material/AccordionSummary';
import IconButton from '@mui/material/IconButton';
import ArrowForwardIosSharpIcon from '@mui/icons-material/ArrowForwardIosSharp';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import {
  FilteredAttackPattern,
  FilteredSubAttackPattern,
  getBoxStyles,
  isSubAttackPatternCovered,
  MinimalAttackPattern,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import AttackPatternsMatrixColumnsElement from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumsElement';
import AttackPatternsMatrixShouldCoverIcon from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixShouldCoverIcon';
import type { Theme } from '../../../../../components/Theme';

interface AccordionAttackPatternProps {
  attackPattern: FilteredAttackPattern;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  attackPatternIdsToOverlap?: string[];
  isSecurityPlatform: boolean;
}

const AccordionAttackPattern = ({
  attackPattern,
  handleOpen,
  attackPatternIdsToOverlap,
  isSecurityPlatform,
}: AccordionAttackPatternProps) => {
  const theme = useTheme<Theme>();
  const [expanded, setExpanded] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const { border, backgroundColor } = getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });

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
      }}
    >
      <MuiAccordionSummary
        onClick={(e) => handleOpen(attackPattern, e)}
        expandIcon={
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
        }
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
        {attackPatternIdsToOverlap?.length !== undefined
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
          borderTop: border,
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
            />
          );
        })}
      </AccordionDetails>
    </MuiAccordion>
  );
};

export default AccordionAttackPattern;
