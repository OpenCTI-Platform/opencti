import React, { useCallback, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Box from '@mui/material/Box';

export interface ContextMenuItem {
  title: string;
  icon?: React.ReactNode;
  onClick: (value: string) => void;
  disabled?: boolean;
}

interface CellContextMenuProps {
  value: string;
  menuItems: ContextMenuItem[];
  children: React.ReactNode;
  onOpenChange?: (isOpen: boolean) => void;
}

const CellContextMenu: React.FC<CellContextMenuProps> = ({
  value,
  menuItems,
  children,
  onOpenChange,
}) => {
  const [anchorPosition, setAnchorPosition] = useState<{ top: number; left: number } | null>(null);
  const open = anchorPosition !== null;

  const handleClose = useCallback(() => {
    setAnchorPosition(null);
    queueMicrotask(() => {
      onOpenChange?.(false);
    });
  }, [onOpenChange]);

  const handleContextMenu = useCallback((event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    setAnchorPosition({ top: event.clientY, left: event.clientX });
    onOpenChange?.(true);
  }, [onOpenChange]);

  const handleItemClick = useCallback(
    (item: ContextMenuItem) => {
      if (!item.disabled) {
        item.onClick(value);
      }
      handleClose();
    },
    [value, handleClose],
  );

  return (
    <>
      <Box onContextMenu={handleContextMenu} sx={{ display: 'contents' }}>
        {children}
      </Box>
      <Menu
        open={open}
        onClose={handleClose}
        anchorReference="anchorPosition"
        anchorPosition={
          anchorPosition
            ? { top: anchorPosition.top, left: anchorPosition.left }
            : undefined
        }
      >
        {menuItems.map((item) => (
          <MenuItem
            key={item.title}
            dense
            disabled={item.disabled}
            onClick={() => handleItemClick(item)}
          >
            {item.icon && <ListItemIcon>{item.icon}</ListItemIcon>}
            <ListItemText>{item.title}</ListItemText>
          </MenuItem>
        ))}
      </Menu>
    </>
  );
};

export default CellContextMenu;
