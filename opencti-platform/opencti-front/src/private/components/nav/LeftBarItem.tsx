import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { alpha, Collapse, ListItemIcon, ListItemText, MenuItem, MenuList, Popover, SxProps, Tooltip } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Theme } from '../../../components/Theme';

interface SubMenuItem {
  type?: string;
  link: string;
  label: string;
  icon?: React.ReactNode;
  exact?: boolean;
  granted?: boolean;
}

interface LeftBarItemProps {
  id: string;
  icon: React.ReactNode;
  label: string;
  link: string;
  exact?: boolean;
  subItems?: SubMenuItem[];
  navOpen: boolean;
  selectedMenu: string[];
  onClick?: () => void;
  onMenuToggle: (id: string) => void;
  onMenuOpen: (id: string) => void;
  onMenuClose: () => void;
  onGoToPage: (event: React.MouseEvent, link: string) => void;
  isMobile: boolean;
  submenuShowIcons?: boolean;
  hiddenEntities?: string[];
}

const LeftBarItem: React.FC<LeftBarItemProps> = ({
  id,
  icon,
  label,
  link,
  exact = false,
  subItems = [],
  navOpen,
  selectedMenu,
  onClick,
  onMenuToggle,
  onMenuOpen,
  onMenuClose,
  onGoToPage,
  isMobile,
  submenuShowIcons = false,
  hiddenEntities = [],
}) => {
  const location = useLocation();
  const theme = useTheme<Theme>();
  const anchorRef = useRef<HTMLLIElement | null>(null);

  const visibleSubItems = subItems.filter(
    (item) => item.granted !== false && (!item.type || !hiddenEntities.includes(item.type)),
  );

  const hasSubItems = visibleSubItems.length > 0;
  const isMenuOpen = selectedMenu.includes(id);

  const isSelected = (itemLink: string, itemExact?: boolean) => {
    if (itemExact) {
      return location.pathname === itemLink;
    }

    // Special case where data and draft shares same url on start
    if (itemLink === '/dashboard/data' && location.pathname.includes('/import/draft/')) {
      return false;
    }

    return location.pathname === itemLink || location.pathname.startsWith(itemLink + '/');
  };

  const isParentSelected = isSelected(link, exact);

  const handleParentClick = (e: React.MouseEvent) => {
    if (hasSubItems) {
      e.preventDefault();
      e.stopPropagation();
      if (isMobile || navOpen) {
        onMenuToggle(id);
      } else {
        onGoToPage(e, link);
      }
    }
  };

  const renderMenuItem = (
    itemIcon: React.ReactNode,
    itemLabel: string,
    selected: boolean,
    showIcon = true,
    fontSize: 'default' | 'small' = 'default',
    forceShowText = false, // For popover items
  ) => {
    const isSubItem = fontSize === 'small';
    const iconColor = isSubItem && selected ? theme.palette.primary.main : 'inherit';
    const iconOpacity = isSubItem && selected ? 1 : 0.5;
    const textColor = isSubItem && selected ? theme.palette.primary.main : 'inherit';

    return (
      <>
        {showIcon && itemIcon && (
          <ListItemIcon
            sx={{
              minWidth: '0px!important',
              mr: 1,
              opacity: iconOpacity,
              color: iconColor,
            }}
          >
            {itemIcon}
          </ListItemIcon>
        )}

        {(navOpen || forceShowText) && (
          <ListItemText
            primary={itemLabel}
            sx={{
              pt: 0.1,
              opacity: fontSize === 'default' || selected ? 1 : 0.6,
            }}
            slotProps={{
              primary: {
                fontSize: fontSize === 'default' ? '14px' : '12px',
                color: textColor,
              },
            }}
          />
        )}
      </>
    );
  };

  // Render submenu item
  const renderSubMenuItem = (item: SubMenuItem, inCollapse: boolean) => {
    const itemSelected = isSelected(item.link, item.exact);

    const menuItem = (
      <MenuItem
        component={Link}
        to={item.link}
        dense
        onClick={inCollapse ? undefined : onMenuClose}
        sx={{ px: 2.5, py: 1 }}
      >
        {renderMenuItem(item.icon, item.label, itemSelected, submenuShowIcons, 'small', !inCollapse)}
      </MenuItem>
    );

    return inCollapse ? (
      <Tooltip key={item.label} title={item.label} placement="right">
        {menuItem}
      </Tooltip>
    ) : (
      <div key={item.label}>{menuItem}</div>
    );
  };

  const getMenuStyles = (selected: boolean): SxProps => {
    return {
      px: 2,
      pr: 1,
      py: 1,
      minHeight: '36px',
      borderLeft: selected ? `2px solid ${theme.palette.primary.main}` : '2px solid transparent',
      backgroundColor: selected ? alpha(theme.palette.primary.main || '#00FF00', 0.1) : 'transparent',
      '&:hover': {
        backgroundColor: selected
          ? theme.palette.action?.selected
          : theme.palette.action?.hover,
      },
    };
  };

  // No Subitems
  if (!hasSubItems) {
    return (
      <Tooltip title={!navOpen ? label : ''} placement="right">
        <MenuItem
          component={Link}
          to={link}
          dense
          onClick={onClick}
          sx={getMenuStyles(isParentSelected)}
        >
          {renderMenuItem(icon, label, isParentSelected)}
        </MenuItem>
      </Tooltip>
    );
  }

  // Nav Opened, collapse subitems
  if (navOpen) {
    return (
      <>
        <MenuItem
          ref={anchorRef}
          dense
          onClick={handleParentClick}
          sx={getMenuStyles(isParentSelected)}
        >
          {renderMenuItem(icon, label, isParentSelected)}
          {isMenuOpen ? <ArrowDropUp /> : <ArrowDropDown />}
        </MenuItem>

        <Collapse in={isMenuOpen} timeout="auto" unmountOnExit>
          <MenuList component="nav" disablePadding>
            {visibleSubItems.map((item) => renderSubMenuItem(item, true))}
          </MenuList>
        </Collapse>
      </>
    );
  }

  // Nav Closed, show popover with subitems
  return (
    <>
      <MenuItem
        ref={anchorRef}
        selected={isParentSelected}
        dense
        onClick={handleParentClick}
        onMouseEnter={() => onMenuOpen(id)}
        onMouseLeave={() => onMenuClose()}
        sx={getMenuStyles(isParentSelected)}
      >
        {renderMenuItem(icon, label, isParentSelected)}
      </MenuItem>

      {
        /*
        * Popover has pointerEvents: 'none' and Paper has pointerEvents: 'auto'
        * This keeps the popover open when the mouse moves from the menu item to the popover
        */
      }
      <Popover
        sx={{ pointerEvents: 'none' }}
        open={isMenuOpen}
        anchorEl={anchorRef.current}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'left' }}
        onClose={onMenuClose}
        disableRestoreFocus
        disableScrollLock
        elevation={0}
        slotProps={{
          paper: {
            onMouseEnter: () => onMenuOpen(id),
            onMouseLeave: onMenuClose,
            sx: {
              pointerEvents: 'auto',
              width: 180,
              backgroundColor: theme.palette.leftBar.popoverItem,
            },
          },
        }}
      >
        <MenuList component="nav" disablePadding>
          {visibleSubItems.map((item) => renderSubMenuItem(item, false))}
        </MenuList>
      </Popover>
    </>
  );
};

export default LeftBarItem;
