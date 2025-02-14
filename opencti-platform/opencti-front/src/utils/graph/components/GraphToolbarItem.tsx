import IconButton, { IconButtonProps } from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import React, { ReactNode } from 'react';

interface GraphToolbarItemProps {
  title: string
  color: IconButtonProps['color']
  Icon: ReactNode
  onClick: IconButtonProps['onClick']
  disabled?: boolean
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
      <span>
        <IconButton
          size="large"
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
