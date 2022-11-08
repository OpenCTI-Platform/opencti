import React, { FunctionComponent } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';

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

const LabelsVocabulariesMenu: FunctionComponent = () => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = useStyles();

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
          to={'/dashboard/settings/vocabularies/labels'}
          selected={
            location.pathname === '/dashboard/settings/vocabularies/labels'
          }
          dense={false}
        >
          <ListItemText primary={t('Labels')} />
        </MenuItem>
        <MenuItem
          component={Link}
          to={'/dashboard/settings/vocabularies/kill_chain_phases'}
          selected={
            location.pathname
            === '/dashboard/settings/vocabularies/kill_chain_phases'
          }
          dense={false}
        >
          <ListItemText primary={t('Kill chain phases')} />
        </MenuItem><MenuItem
          component={Link}
          to={'/dashboard/settings/vocabularies/fields'}
          selected={
            location.pathname
            === '/dashboard/settings/vocabularies/fields'
          }
          dense={false}
        >
          <ListItemText primary={t('Vocabularies')} />
        </MenuItem>
      </MenuList>
    </Drawer>
  );
};

export default LabelsVocabulariesMenu;
