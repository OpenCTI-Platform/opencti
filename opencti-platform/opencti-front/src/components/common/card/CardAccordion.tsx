import { ReactNode, useState } from 'react';
import { ExpandMore } from '@mui/icons-material';
import { Accordion, AccordionDetails, AccordionSummary, SxProps } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../Theme';
import Card from './Card';

interface ChildrenProps {
  changeState: (open: boolean) => void;
}

interface CardAccordionProps {
  title?: string;
  action?: ReactNode;
  preview: ReactNode;
  children?: ReactNode | ((props: ChildrenProps) => ReactNode);
  onStateChange?: (open: boolean) => void;
}

const CardAccordion = ({
  title,
  action,
  children,
  preview,
  onStateChange,
}: CardAccordionProps) => {
  const theme = useTheme<Theme>();
  const [expanded, setExpanded] = useState(false);

  const containerSx: SxProps = {
    padding: theme.spacing(3),
    background: theme.palette.background.secondary,
  };

  const summarySx: SxProps = {
    padding: 0,
    minHeight: 0,
    '.MuiAccordionSummary-content': {
      margin: 0,
    },
    '.MuiAccordionSummary-content.Mui-expanded': {
      margin: 0,
    },
  };

  const detailsSx: SxProps = {
    borderTop: `1px solid ${theme.palette.border.paper}`,
    padding: 0,
    marginTop: theme.spacing(2),
    paddingTop: theme.spacing(2),
  };

  return (
    <Card title={title} action={action} noPadding>
      <Accordion
        expanded={expanded}
        onChange={(_, val) => {
          setExpanded(val);
          onStateChange?.(val);
        }}
        sx={containerSx}
        slotProps={{ transition: { unmountOnExit: false } }}
      >
        <AccordionSummary
          sx={summarySx}
          expandIcon={<ExpandMore sx={{ color: theme.palette.primary.main }} />}
        >
          {preview}
        </AccordionSummary>
        <AccordionDetails sx={detailsSx}>
          {typeof children === 'function'
            ? children({ changeState: setExpanded })
            : children
          }
        </AccordionDetails>
      </Accordion>
    </Card>
  );
};

export default CardAccordion;
