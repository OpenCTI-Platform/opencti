import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';

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

const ProcessingMenu = () => {
  const location = useLocation();
  const classes = useStyles();
  const { t } = useFormatter();
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
          to={'/dashboard/data/processing/automation'}
          selected={location.pathname.includes(
            '/dashboard/data/processing/automation',
          )}
          dense={false}
        >
          <ListItemText primary={t('Automation')} />
        </MenuItem>
        <MenuItem
          component={Link}
          to={'/dashboard/data/processing/tasks'}
          selected={location.pathname === '/dashboard/data/processing/tasks'}
          dense={false}
        >
          <ListItemText primary={t('Tasks')} />
        </MenuItem>
      </MenuList>
    </Drawer>
  );
};

export default ProcessingMenu;
