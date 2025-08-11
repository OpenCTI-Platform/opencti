import React, { PropsWithChildren, ReactNode } from 'react';
import { ExpandMore } from '@mui/icons-material';
import { Accordion, AccordionDetails, AccordionSummary } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';
import PaperHeader, { PaperHeaderProps } from './PaperHeader';

interface PaperAccordionProps extends PaperHeaderProps, PropsWithChildren {
  preview: ReactNode
}

const PaperAccordion = ({ title, actions, children, preview }: PaperAccordionProps) => {
  const theme = useTheme<Theme>();

  return (
    <div>
      <PaperHeader title={title} actions={actions} />
      <div style={{ marginTop: title || actions ? theme.spacing(1) : 0 }}>
        <Accordion
          slotProps={{ transition: { unmountOnExit: false } }}
          sx={{
            padding: 2,
            background: theme.palette.background.paper,
            border: `1px solid ${theme.palette.border.paper}`,
          }}
        >
          <AccordionSummary
            sx={{
              padding: 0,
              '.MuiAccordionSummary-content': {
                margin: 0,
              },
              '.MuiAccordionSummary-content.Mui-expanded': {
                margin: 0,
              },
            }}
            expandIcon={<ExpandMore sx={{ color: theme.palette.primary.main }} />}
          >
            {preview}
          </AccordionSummary>
          <AccordionDetails
            sx={{
              borderTop: `1px solid ${theme.palette.border.paper}`,
              padding: 0,
              marginTop: theme.spacing(2),
              paddingTop: theme.spacing(2),
            }}
          >
            {children}
          </AccordionDetails>
        </Accordion>
      </div>
    </div>
  );
};

export default PaperAccordion;
