import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  drawer: {
    minHeight: '100vh',
    width: 200,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
  },
  toolbar: theme.mixins.toolbar,
});

class SharingMenu extends Component {
  render() {
    const { t, location, classes } = this.props;
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
            to={'/dashboard/data/sharing/streams'}
            selected={location.pathname === '/dashboard/data/sharing/streams'}
            dense={false}
          >
            <ListItemText primary={t('Live streams')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={'/dashboard/data/sharing/feeds'}
            selected={location.pathname.includes(
              '/dashboard/data/sharing/feeds',
            )}
            dense={false}
          >
            <ListItemText primary={t('Feeds (CSV)')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={'/dashboard/data/sharing/taxii'}
            selected={location.pathname.includes(
              '/dashboard/data/sharing/taxii',
            )}
            dense={false}
          >
            <ListItemText primary={t('TAXII collections')} />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

SharingMenu.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withRouter, withStyles(styles))(SharingMenu);
