import { styled, useTheme } from '@mui/material/styles';
import MuiAccordion from '@mui/material/Accordion';
import MuiAccordionSummary from '@mui/material/AccordionSummary';
import ArrowForwardIosSharpIcon from '@mui/icons-material/ArrowForwardIosSharp';
import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Box } from '@mui/material';

export const Accordion = styled((props) => (<MuiAccordion disableGutters elevation={0} square {...props} />))(() => ({
  border: '1px solid rgba(255, 255, 255, 0.7)',
  '&:before': {
    display: 'none',
  },
  borderRadius: '4px',
  backgroundColor: 'rgba(255, 255, 255, 0)',
}));

export const AccordionSummary = styled((props) => (
  <MuiAccordionSummary expandIcon={<ArrowForwardIosSharpIcon sx={{ fontSize: '0.9rem' }} />} {...props}/>
))(({ theme }) => ({
  backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, .05)' : 'rgba(0, 0, 0, .03)',
  flexDirection: 'row-reverse',
  '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
    transform: 'rotate(90deg)',
  },
  '& .MuiAccordionSummary-content': {
    marginLeft: theme.spacing(1),
  },
}));

export const AccordionAttackPattern = ({ ap, handleToggleHover, handleOpen, colorArray, hover, colors, level, position }) => {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);

  const handleToggleAccordion = (event) => {
    event.stopPropagation();
    setExpanded(!expanded);
  };

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
        backgroundColor: colorArray[0][1],
        border: `1px solid ${colorArray[level][0]}`,
      }}
    >
      <MuiAccordionSummary
        onClick={(e) => handleOpen(ap, e)}
        expandIcon={
          <IconButton onClick={handleToggleAccordion}>
            <ArrowForwardIosSharpIcon sx={{
              fontSize: '0.9rem',
            }}
            />
          </IconButton>
        }
        sx={{
          minHeight: 0,
          paddingLeft: 0,
          backgroundColor: colorArray[level][position],
          flexDirection: 'row-reverse',
          '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
            transform: 'rotate(90deg)',
          },
          '.MuiAccordionSummary-content': { marginBlock: 1.25 }
        }}
      >
        <Typography variant="body2" fontSize={10}>
          {ap.name}
        </Typography>
      </MuiAccordionSummary>
      <AccordionDetails
        sx={{
          padding: `0 0 0 ${theme.spacing(2)}`,
          borderTop: `1px solid ${colorArray[level][0]}`,
        }}
      >
        {ap.subAttackPatterns.map((subAttackPattern) => {
          const isSubHovered = hover[subAttackPattern.attack_pattern_id];
          const subLevel = isSubHovered && subAttackPattern.level !== 0 ? subAttackPattern.level - 1 : subAttackPattern.level;
          const subPosition = isSubHovered && subLevel === 0 ? 2 : 1;
          const subColorArray = colors(theme.palette.background.accent);
          return (
            <Box
              key={subAttackPattern.attack_pattern_id}
              onMouseEnter={() => handleToggleHover(subAttackPattern.attack_pattern_id)}
              onMouseLeave={() => handleToggleHover(subAttackPattern.attack_pattern_id)}
              onClick={(e) => handleOpen(subAttackPattern, e)}
              sx={{
                cursor: 'pointer',
                border: `1px solid ${subColorArray[subLevel][0]}`,
                backgroundColor: subColorArray[subLevel][subPosition],
                padding: 1.25,
              }}
            >
              <Typography variant="body2" fontSize={10}>
                {subAttackPattern.name}
              </Typography>
            </Box>
          );
        })}
      </AccordionDetails>
    </MuiAccordion>
  );
};
