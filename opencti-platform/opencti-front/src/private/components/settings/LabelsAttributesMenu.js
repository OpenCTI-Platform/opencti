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
    backgroundColor: theme.palette.background.navLight,
  },
  toolbar: theme.mixins.toolbar,
});

class LabelsAttributesMenu extends Component {
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
            to={'/dashboard/settings/attributes/labels'}
            selected={
              location.pathname === '/dashboard/settings/attributes/labels'
            }
            dense={false}
          >
            <ListItemText primary={t('Labels')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={'/dashboard/settings/attributes/kill_chain_phases'}
            selected={
              location.pathname
              === '/dashboard/settings/attributes/kill_chain_phases'
            }
            dense={false}
          >
            <ListItemText primary={t('Kill chain phases')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={'/dashboard/settings/attributes/fields/report_types'}
            selected={
              location.pathname
              === '/dashboard/settings/attributes/fields/report_types'
            }
            dense={false}
          >
            <ListItemText primary={t('Report types')} />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

LabelsAttributesMenu.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(LabelsAttributesMenu);
