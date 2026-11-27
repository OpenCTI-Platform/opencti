import React, { FunctionComponent, ReactNode } from 'react';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../components/Theme';

interface ConfigPresetStickyFooterProps {
  children: ReactNode;
  // A line above the footer, for a list that scrolls under it
  hasBorder?: boolean;
}

// The actions of a step of the import dialog: they stay at the bottom of the visible part while the list above scrolls, and at the end of
// the content when it is shorter. They are never the last row of a list that grows (infinite scroll), where they would be pushed down by each page.
const ConfigPresetStickyFooter: FunctionComponent<ConfigPresetStickyFooterProps> = ({ children, hasBorder = false }) => {
  const theme = useTheme<Theme>();
  return (
    <div
      data-testid="config-preset-sticky-footer"
      style={{
        position: 'sticky',
        bottom: 0,
        zIndex: 1,
        marginTop: 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: theme.spacing(2),
        paddingTop: theme.spacing(2),
        // The surface of the dialog, so that the footer hides what scrolls under it without drawing a box of its own
        background: 'var(--bg-elevation-default)',
        // The scroll area of the Dialog has a 4px vertical padding below the sticky footer, where the list would show through
        boxShadow: `0 ${theme.spacing(0.5)} 0 0 var(--bg-elevation-default)`,
        ...(hasBorder ? { borderTop: `1px solid ${theme.palette.divider}` } : {}),
      }}
    >
      {children}
    </div>
  );
};

export default ConfigPresetStickyFooter;
