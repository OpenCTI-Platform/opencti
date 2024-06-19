import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import EEMenu from '../common/entreprise_edition/EEMenu';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useGranted, { KNOWLEDGE_KNUPDATE, SETTINGS_SETACCESSES, CSVMAPPERS } from '../../../utils/hooks/useGranted';

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

const ProcessingMenu = () => {
  const location = useLocation();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const isAdministrator = useGranted([SETTINGS_SETACCESSES]);
  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]);
  const isCsvMapperUpdater = useGranted([CSVMAPPERS]);
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
        {isAdministrator && (
          <MenuItem
            component={Link}
            to={'/dashboard/data/processing/automation'}
            selected={location.pathname.includes(
              '/dashboard/data/processing/automation',
            )}
            dense={false}
          >
            <ListItemText primary={<EEMenu>{t_i18n('Automation')}</EEMenu>} />
          </MenuItem>
        )}
        {isKnowledgeUpdater && (
          <MenuItem
            component={Link}
            to={'/dashboard/data/processing/tasks'}
            selected={location.pathname === '/dashboard/data/processing/tasks'}
            dense={false}
          >
            <ListItemText primary={t_i18n('Tasks')} />
          </MenuItem>
        )}
        {isCsvMapperUpdater && (
          <MenuItem
            component={Link}
            to={'/dashboard/data/processing/csv_mapper'}
            selected={location.pathname.includes(
              '/dashboard/data/processing/csv_mapper',
            )}
            dense={false}
          >
            <ListItemText primary={t_i18n('CSV Mappers')} />
          </MenuItem>
        )}
      </MenuList>
    </Drawer>
  );
};

export default ProcessingMenu;
