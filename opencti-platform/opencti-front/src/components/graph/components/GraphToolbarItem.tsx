import IconButton, { IconButtonProps } from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import React, { ReactNode } from 'react';

interface GraphToolbarItemProps {
  title: string;
  color: IconButtonProps['color'];
  Icon: ReactNode;
  onClick: IconButtonProps['onClick'];
  disabled?: boolean;
}

const GraphToolbarItem = ({
  title,
  color,
  Icon,
  onClick,
  disabled,
}: GraphToolbarItemProps) => {
  return (
    <Tooltip title={title}>
      {/* A disabled button fires no pointer events, so the span carries the tooltip.
          inline-flex keeps the button's size and alignment in the toolbar. */}
      <span
        style={{ display: 'inline-flex' }}
        // Known gap: the focusable span lets keyboard users reach a disabled tool's tooltip.
        // The fix is an aria-disabled IconButton with no wrapper (WAI-ARIA APG,
        // "Focusability of disabled controls"), deferred out of this change.
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={disabled ? 0 : undefined}
      >
        <IconButton
          aria-label={title}
          color={color}
          onClick={onClick}
          disabled={disabled}
        >
          {Icon}
        </IconButton>
      </span>
    </Tooltip>
  );
};

export default GraphToolbarItem;
