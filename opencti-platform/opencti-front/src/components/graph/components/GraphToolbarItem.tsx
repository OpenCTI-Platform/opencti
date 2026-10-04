import React, { MouseEvent, ReactNode } from 'react';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

interface GraphToolbarItemProps {
  title: string;
  /** `secondary` marks a tool that is on (a mode, a layout, a filter in use). */
  color: 'primary' | 'secondary';
  Icon: ReactNode;
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
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
    <Tooltip>
      <TooltipTrigger asChild>
        <IconButton
          priority="tertiary"
          aria-label={title}
          active={color === 'secondary'}
          onClick={onClick}
          disabled={disabled}
          icon={Icon}
        />
      </TooltipTrigger>
      <TooltipContent>{title}</TooltipContent>
    </Tooltip>
  );
};

export default GraphToolbarItem;
