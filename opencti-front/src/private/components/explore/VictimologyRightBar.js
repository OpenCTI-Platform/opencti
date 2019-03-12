import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Drawer from '@material-ui/core/Drawer';
import { Timeline, PieChart } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 0 20px 0',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  listIcon: {
    marginRight: 0,
  },
  toolbar: theme.mixins.toolbar,
});

class VictimologyRightBar extends Component {
  render() {
    const {
      t, classes, location, threatId,
    } = this.props;
    return (
      <Drawer variant='permanent' anchor='right' classes={{ paper: classes.drawerPaper }}>
        <div className={classes.toolbar}/>
        <MenuList component='nav'>
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} divider={true} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/distribution`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/distribution` } dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <PieChart/>
            </ListItemIcon>
            <ListItemText
              primary={t('Distribution')}
              secondary={t('Distributions of targets')}
              classes={{ root: classes.listText }}
            />
          </MenuItem>
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} divider={true} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/time`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/time`} dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Timeline/>
            </ListItemIcon>
            <ListItemText
              primary={t('Time series')}
              secondary={t('Series of targeting events')}
              classes={{ root: classes.listText }}
            />
          </MenuItem>
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} divider={true} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/localization`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/localization`} dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Timeline/>
            </ListItemIcon>
            <ListItemText
              primary={t('Localization')}
              classes={{ root: classes.listText }}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

VictimologyRightBar.propTypes = {
  threatId: PropTypes.string,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(VictimologyRightBar);
