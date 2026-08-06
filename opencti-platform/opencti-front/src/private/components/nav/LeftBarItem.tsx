import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { alpha, Collapse, List, ListItem, ListItemButton, ListItemIcon, ListItemText, MenuItem, MenuList, Popover, SxProps, Tooltip } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Theme } from '../../../components/Theme';
import useDraftContext from '../../../utils/hooks/useDraftContext';

interface SubMenuItem {
  type?: string;
  link: string;
  label: string;
  icon?: React.ReactElement;
  exact?: boolean;
  granted?: boolean;
}

interface LeftBarItemProps {
  id: string;
  icon: React.ReactElement;
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
  onMenuClose,
  submenuShowIcons = false,
  hiddenEntities = [],
}) => {
  const location = useLocation();
  const theme = useTheme<Theme>();
  const draftContext = useDraftContext();
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
      onMenuToggle(id);
    }
  };

  const handleListKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Tab') {
      event.preventDefault();
      onMenuClose();
    } else if (event.key === 'Escape') {
      onMenuClose();
    }
  };

  const renderMenuItem = (
    itemLabel: string,
    selected: boolean,
    showIcon = true,
    fontSize: 'default' | 'small' = 'default',
    forceShowText = false, // For popover items
    itemIcon?: React.ReactElement,
  ) => {
    const isSubItem = fontSize === 'small';
    const iconColor = selected ? theme.palette.text.light : theme.palette.text.tertiary;
    const iconOpacity = isSubItem && selected ? 1 : 0.5;

    const getTextColor = () => {
      if (isSubItem && draftContext && selected) {
        return theme.palette.designSystem.alert.warning.primary;
      }
      if (isSubItem && selected) {
        return theme.palette.primary.main;
      }
      if (isSubItem && theme.palette.leftBar.text) {
        return theme.palette.text.light;
      }
      if (theme.palette.leftBar.text) {
        return theme.palette.leftBar.text;
      }
      return 'inherit';
    };

    return (
      <>
        {showIcon && itemIcon && (
          <ListItemIcon
            sx={{
              minWidth: '0px!important',
              mr: 1,
              opacity: iconOpacity,
              color: iconColor,
              '& svg': {
                fontSize: '16px!important',
              },
            }}
          >
            <Tooltip key={itemLabel} title={itemLabel} placement="right">
              {itemIcon}
            </Tooltip>

          </ListItemIcon>
        )}

        {(navOpen || forceShowText) && (
          <ListItemText
            primary={itemLabel}
            sx={{
              pt: 0.1,
            }}
            slotProps={{
              primary: {
                fontSize: fontSize === 'default' ? '14px' : '12px',
                color: getTextColor(),
              },
            }}
          />
        )}
      </>
    );
  };

  // Render submenu item
  const renderSubMenuItem = (item: SubMenuItem, inCollapse: boolean, index: number) => {
    const itemSelected = isSelected(item.link, item.exact);
    return inCollapse ? (
      <ListItemButton
        key={`sub-menu-${index}`}
        component={Link}
        to={item.link}
        dense
        onClick={inCollapse ? undefined : onMenuClose}
        sx={{
          px: 2.5,
          py: 1,
          '&:hover': {
            backgroundColor: theme.palette.leftBar.hover,
          },
        }}
      >
        {renderMenuItem(item.label, itemSelected, submenuShowIcons, 'small', !inCollapse, item.icon)}
      </ListItemButton>
    ) : (
      <MenuItem
        key={`sub-menu-${index}`}
        component={Link}
        to={item.link}
        dense
        onClick={inCollapse ? undefined : onMenuClose}
        sx={{
          px: 2.5,
          py: 1,
          '&:hover': {
            backgroundColor: theme.palette.leftBar.hover,
          },
        }}
      >
        {renderMenuItem(item.label, itemSelected, submenuShowIcons, 'small', !inCollapse, item.icon)}
      </MenuItem>
    );
  };

  const getMenuStyles = (selected: boolean): SxProps => {
    const draftBg = theme.palette.designSystem.alert.warning.primary;
    const defaultBg = draftContext ? draftBg : theme.palette.primary.main;
    return {
      px: 2,
      pr: 1,
      py: 0,
      height: '36px',
      borderLeft: selected ? `2px solid ${defaultBg}` : '2px solid transparent',
      backgroundColor: selected ? alpha(defaultBg || '#00FF00', 0.1) : 'transparent',
      display: 'flex',
      alignItems: 'center',
      '&:hover': {
        backgroundColor: selected
          ? theme.palette.action?.selected
          : theme.palette.leftBar.hover,
      },
    };
  };

  // No Subitems
  if (!hasSubItems) {
    return (
      <ListItem disableGutters disablePadding dense>
        <Tooltip title={!navOpen ? label : ''} placement="right">
          <ListItemButton
            component={Link}
            to={link}
            dense
            onClick={onClick}
            sx={getMenuStyles(isParentSelected)}
          >
            {renderMenuItem(label, isParentSelected, undefined, undefined, undefined, icon)}
          </ListItemButton>
        </Tooltip>
      </ListItem>
    );
  }

  // Nav Opened, collapse subitems
  if (navOpen) {
    return (
      <>
        <ListItemButton
          id={`nav-button-${label}`}
          dense
          aria-expanded={isMenuOpen}
          aria-controls={`nav-${label}-collapse`}
          onClick={handleParentClick}
          sx={getMenuStyles(isParentSelected)}
        >
          {renderMenuItem(label, isParentSelected, undefined, undefined, undefined, icon)}
          {isMenuOpen ? <ArrowDropUp sx={{ fontSize: '20px' }} /> : <ArrowDropDown sx={{ fontSize: '20px' }} />}
        </ListItemButton>

        <Collapse in={isMenuOpen} timeout="auto" unmountOnExit>
          <List
            id={`nav-${label}-collapse`}
            aria-labelledby={`nav-button-${label}`}
            role="region"
            disablePadding
            sx={{ backgroundColor: theme.palette.designSystem.background.main }}
          >
            {visibleSubItems.map((item, i) => renderSubMenuItem(item, true, i))}
          </List>
        </Collapse>
      </>
    );
  }

  // Nav Closed, show popover with subitems
  return (
    <>
      <span ref={anchorRef}>
        <ListItemButton
          tabIndex={0}
          id={`nav-${label}`}
          aria-expanded={isMenuOpen}
          aria-haspopup="menu"
          aria-controls={isMenuOpen ? `${label}-sub-menu` : undefined}
          onClick={handleParentClick}
          sx={getMenuStyles(isParentSelected)}
        >
          {renderMenuItem(label, isParentSelected, undefined, undefined, undefined, icon)}
        </ListItemButton>
      </span>
      <Popover
        open={isMenuOpen}
        anchorEl={anchorRef.current}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'left' }}
        onClose={onMenuClose}
        disableScrollLock
        elevation={0}
        slotProps={{
          paper: {
            onMouseLeave: onMenuClose,
            sx: {
              pointerEvents: 'auto',
              width: 180,
              backgroundColor: theme.palette.leftBar.popoverItem,
            },
          },
        }}
      >
        <MenuList
          variant="menu"
          autoFocusItem={isMenuOpen}
          disablePadding
          id={`${label}-sub-menu`}
          onKeyDown={handleListKeyDown}
        >
          {visibleSubItems.map((item, i) => renderSubMenuItem(item, false, i))}
        </MenuList>
      </Popover>
    </>
  );
};

export default LeftBarItem;
