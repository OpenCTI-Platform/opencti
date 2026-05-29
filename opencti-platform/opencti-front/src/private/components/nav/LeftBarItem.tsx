import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { alpha, Box, Collapse, ListItemIcon, ListItemText, MenuItem, MenuList, Popover, SxProps, Tooltip } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { useMemo, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Theme } from '../../../components/Theme';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../components/i18n';

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
    fontSize: string = '10px',
    // forceShowText = false, // For popover items
  ) => {
    const isSubItem = fontSize === 'small';
    const iconColor = selected ? 'var(--fluent-color-primary)' : theme.palette.text.tertiary;
    const iconOpacity = 1;

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
          <Box sx={{ display: 'flex', width: '100%', flexDirection: 'column', alignItems: 'center' }}>
            <ListItemIcon
              sx={{
                minWidth: '0px!important',
                opacity: iconOpacity,
                color: iconColor,
                ...(isSubItem && { alignSelf: 'flex-start', pt: 0.35 }),
                '& svg': {
                  fontSize: '24px!important',
                },
              }}
            >
              {itemIcon}
            </ListItemIcon>

            {/* {(navOpen || forceShowText) && ( */}
            <ListItemText
              primary={itemLabel}
              sx={{
                pt: 0.1,
                ...(isSubItem && { flex: 1, minWidth: 0 }),
              }}
              slotProps={{
                primary: {
                  fontSize: fontSize,
                  color: getTextColor(),
                  ...(isSubItem && {
                    whiteSpace: 'normal',
                    lineHeight: 1.35,
                    wordBreak: 'break-word',
                  }),
                },
              }}

            />
            {/* )} */}
          </Box>
        )}
        {!showIcon && (
          <ListItemText
            primary={itemLabel}
            sx={{
              pt: 0.1,
              ...(isSubItem && { flex: 1, minWidth: 0 }),
            }}
            slotProps={{
              primary: {
                fontSize: fontSize,
                color: getTextColor(),
                ...(isSubItem && {
                  whiteSpace: 'normal',
                  lineHeight: 1.35,
                  wordBreak: 'break-word',
                }),
              },
            }}
          />
        )}
      </>
    );
  };
  const { t_i18n } = useFormatter();

  // Render submenu item
  const renderSubMenuItem = (item: SubMenuItem, inCollapse: boolean) => {
    const itemSelected = isSelected(item.link, item.exact);

    const menuItem = (
      <MenuItem
        component={Link}
        to={item.link}
        onClick={inCollapse ? undefined : onMenuClose}
        sx={{
          alignItems: 'flex-start',
          px: 2.5,
          py: 1,
          minHeight: 'unset',
          '&:hover': {
            backgroundColor: theme.palette.leftBar.hover,
          },
        }}
      >
        {renderMenuItem(item.icon, item.label, itemSelected, false, '14px')}
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
    const draftBg = theme.palette.designSystem.alert.warning.primary;
    const defaultBg = draftContext ? draftBg : theme.palette.primary.main;
    return {
      px: 1,
      pr: 1,
      py: 0,
      marginInlineStart: 1,
      height: '56px',
      borderRadius: '0 !important',
      borderLeft: selected ? `2px solid ${defaultBg}` : '2px solid transparent',
      backgroundColor: 'transparent',
      color: selected ? 'var(--fluent-color-primary)' : 'inherit',
      display: 'flex',
      alignItems: 'center',
      '&:hover': {
        color: 'var(--fluent-color-primary)',
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
          {isMenuOpen ? <ArrowDropUp sx={{ fontSize: '20px' }} /> : <ArrowDropDown sx={{ fontSize: '20px' }} />}
        </MenuItem>

        <Collapse in={isMenuOpen} timeout="auto" unmountOnExit>
          <MenuList component="nav" disablePadding sx={{ backgroundColor: theme.palette.designSystem.background.main }}>
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
        anchorOrigin={{ vertical: 'top', horizontal: t_i18n('direction') === 'rtl' ? 'left' : 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: t_i18n('direction') === 'rtl' ? 'right' : 'left' }}
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
              minWidth: 200,
              maxWidth: 300,
              boxShadow: '0 0 10px 0 rgba(0, 0, 0, 0.1)',
              backgroundColor: 'var(--fluent-color-bg)',
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
