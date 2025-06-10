import { useTheme } from '@mui/material/styles';
import React, { useState } from 'react';
import MuiAccordion from '@mui/material/Accordion';
import MuiAccordionSummary from '@mui/material/AccordionSummary';
import IconButton from '@mui/material/IconButton';
import ArrowForwardIosSharpIcon from '@mui/icons-material/ArrowForwardIosSharp';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Box, Tooltip } from '@mui/material';
import { FilteredAttackPattern, FilteredSubAttackPattern, getBoxStyles, MinimalAttackPattern } from '@components/techniques/attack_patterns/AttackPatternsMatrixColumns';
import { CheckOutlined, CloseOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface AccordionAttackPatternProps {
  ap: FilteredAttackPattern,
  handleToggleHover: (id: string) => void,
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void,
  hover: Record<string, boolean>,
  border: string,
  backgroundColor: string,
  isSecurityPlatformEnabled: boolean,
  attackPatternIdsToOverlap?: string[]
}

const AccordionAttackPattern = ({
  ap,
  handleToggleHover,
  handleOpen,
  hover,
  border,
  backgroundColor,
  isSecurityPlatformEnabled,
  attackPatternIdsToOverlap,
}: AccordionAttackPatternProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [expanded, setExpanded] = useState(false);

  return (
    <MuiAccordion
      expanded={expanded}
      square
      disableGutters
      elevation={0}
      id={ap.attack_pattern_id}
      key={ap.attack_pattern_id}
      slotProps={{ transition: { unmountOnExit: true } }}
      onMouseEnter={() => handleToggleHover(ap.attack_pattern_id)}
      onMouseLeave={() => handleToggleHover(ap.attack_pattern_id)}
      sx={{
        width: '100%',
        border,
        backgroundColor: 'transparent',
      }}
    >
      <MuiAccordionSummary
        onClick={(e) => handleOpen(ap, e)}
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
          backgroundColor,
          whiteSpace: 'wrap',
          flexDirection: 'row-reverse',
          '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
            transform: 'rotate(90deg)',
          },
          '.MuiAccordionSummary-content': { marginBlock: 1.25 },
        }}
      >
        <Typography variant="body2" fontSize={10}>
          {ap.name}
        </Typography>
      </MuiAccordionSummary>
      <AccordionDetails
        sx={{
          padding: `0 0 0 ${theme.spacing(2)}`,
          borderTop: border,
        }}
      >
        {ap.subAttackPatterns?.map((subAttackPattern: FilteredSubAttackPattern) => {
          const isSubHovered = hover[subAttackPattern.attack_pattern_id];
          const hasSubLevel = subAttackPattern.level > 0;
          return (
            <Box
              key={subAttackPattern.attack_pattern_id}
              onMouseEnter={() => handleToggleHover(subAttackPattern.attack_pattern_id)}
              onMouseLeave={() => handleToggleHover(subAttackPattern.attack_pattern_id)}
              onClick={(e) => handleOpen(subAttackPattern, e)}
              sx={{
                display: 'flex',
                cursor: 'pointer',
                ...getBoxStyles(hasSubLevel, isSubHovered, theme),
                padding: 1.25,
                justifyContent: 'space-between',
                gap: 1,
                alignItems: 'center',
                whiteSpace: 'normal',
                width: '100%',
              }}
            >
              <Typography variant="body2" fontSize={10}>
                {subAttackPattern.name}
              </Typography>
              {isSecurityPlatformEnabled && attackPatternIdsToOverlap?.length !== undefined && ap.level > 0 && (
                <Tooltip
                  title={t_i18n('Should cover')}
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    height: 19,
                  }}
                >
                  {subAttackPattern.isOverlapping
                    ? <CheckOutlined fontSize="medium" color="success" />
                    : <CloseOutlined fontSize="medium" color="error" />
                  }
                </Tooltip>
              )}
            </Box>
          );
        })}
      </AccordionDetails>
    </MuiAccordion>
  );
};

export default AccordionAttackPattern;
