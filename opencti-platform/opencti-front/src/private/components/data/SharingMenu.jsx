import React from 'react';
import { Link, useLocation } from 'react-router';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  drawer: {
    minHeight: '100vh',
    width: 200,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
  },
  toolbar: theme.mixins.toolbar,
}));

const SharingMenu = () => {
  const location = useLocation();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  return (
    <Drawer
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawer }}
    >
      <div className={classes.toolbar} />
      <MenuList
        component="nav"
        style={{ marginTop: bannerHeightNumber + settingsMessagesBannerHeight }}
        sx={{ marginBottom: bannerHeightNumber }}
      >
        <MenuItem
          component={Link}
          to={'/dashboard/data/sharing/streams'}
          selected={location.pathname === '/dashboard/data/sharing/streams'}
          dense={false}
        >
          <ListItemText primary={t_i18n('Live streams')} />
        </MenuItem>
        <MenuItem
          component={Link}
          to={'/dashboard/data/sharing/feeds'}
          selected={location.pathname.includes('/dashboard/data/sharing/feeds')}
          dense={false}
        >
          <ListItemText primary={t_i18n('CSV feeds')} />
        </MenuItem>
        <MenuItem
          component={Link}
          to={'/dashboard/data/sharing/taxii'}
          selected={location.pathname.includes('/dashboard/data/sharing/taxii')}
          dense={false}
        >
          <ListItemText primary={t_i18n('TAXII collections')} />
        </MenuItem>
      </MenuList>
    </Drawer>
  );
};

export default SharingMenu;
