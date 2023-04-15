import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';

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
  const { t } = useFormatter();
  return (
    <Drawer
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawer }}
    >
      <div className={classes.toolbar} />
      <MenuList component="nav">
        <MenuItem
          component={Link}
          to={'/dashboard/data/ingestion/sync'}
          selected={location.pathname === '/dashboard/data/ingestion/sync'}
          dense={false}
        >
          <ListItemText primary={t('Remote OCTI Streams')} />
        </MenuItem>
        <MenuItem
          component={Link}
          to={'/dashboard/data/ingestion/taxii'}
          selected={location.pathname.includes(
            '/dashboard/data/ingestion/taxii',
          )}
          dense={false}
          disabled={true}
        >
          <ListItemText primary={t('TAXII Feeds')} />
        </MenuItem>
      </MenuList>
    </Drawer>
  );
};

export default SharingMenu;
