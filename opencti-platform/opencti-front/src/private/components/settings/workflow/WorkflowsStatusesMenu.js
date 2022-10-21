import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles((theme) => ({
  drawer: {
    minHeight: '100vh',
    width: 200,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
    backgroundColor: theme.palette.background.navLight,
  },
  toolbar: theme.mixins.toolbar,
}));

const WorkflowsStatusesMenu = () => {
  const classes = useStyles();
  const { t } = useFormatter();
  const location = useLocation();

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
          to={'/dashboard/settings/workflow/workflows'}
          selected={
            location.pathname === '/dashboard/settings/workflow/workflows'
          }
          dense={false}
        >
          <ListItemText primary={t('Workflows')} />
        </MenuItem>
        <MenuItem
          component={Link}
          to={'/dashboard/settings/workflow/statusTemplates'}
          selected={
            location.pathname === '/dashboard/settings/workflow/statusTemplates'
          }
          dense={false}
        >
          <ListItemText primary={t('Status Templates')} />
        </MenuItem>
      </MenuList>
    </Drawer>
  );
};

export default WorkflowsStatusesMenu;
