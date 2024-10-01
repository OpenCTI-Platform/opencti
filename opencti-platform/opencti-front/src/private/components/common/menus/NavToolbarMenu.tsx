import React, { FunctionComponent, ReactElement } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  drawer: {
    minHeight: '100vh',
    width: 200,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
    backgroundColor: theme.palette.background.nav,
  },
  toolbar: theme.mixins.toolbar,
}));

export interface MenuEntry {
  path: string;
  label: string;
  icon?: ReactElement;
}

const NavToolbarMenu: FunctionComponent<{ entries: MenuEntry[] }> = ({ entries }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const { bannerSettings } = useAuth();
  const bannerHeight = bannerSettings.bannerHeightNumber;
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  return (
    <Drawer variant="permanent" anchor="right" classes={{ paper: classes.drawer }}>
      <div className={classes.toolbar} />
      <MenuList component="nav" style={{ marginTop: bannerHeight + settingsMessagesBannerHeight, marginBottom: bannerHeight }}>
        {entries.map((entry, idx) => {
          return (
            <MenuItem
              key={idx}
              component={Link}
              to={entry.path}
              selected={location.pathname.startsWith(entry.path)}
              dense={false}
            >
              {entry.icon && (
              <ListItemIcon>
                {entry.icon}
              </ListItemIcon>
              )}
              <ListItemText primary={t_i18n(entry.label)} />
            </MenuItem>
          );
        })}
      </MenuList>
    </Drawer>
  );
};

export default NavToolbarMenu;
