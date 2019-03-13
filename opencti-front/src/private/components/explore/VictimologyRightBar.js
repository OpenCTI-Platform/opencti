import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Divider from '@material-ui/core/Divider';
import Drawer from '@material-ui/core/Drawer';
import { Compare }  from '@material-ui/icons';
import { ChartTimeline, ChartDonutVariant, Hubspot } from 'mdi-material-ui';
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
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/distribution`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/distribution` } dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <ChartDonutVariant/>
            </ListItemIcon>
            <ListItemText
              primary={t('Distribution')}
              secondary={t('Targeting types')}
              classes={{ root: classes.listText }}
            />
          </MenuItem>
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/time`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/time`} dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <ChartTimeline/>
            </ListItemIcon>
            <ListItemText
              primary={t('Evolution')}
              secondary={t('Targeting through time')}
              classes={{ root: classes.listText }}
            />
          </MenuItem>
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/knowledge`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/knowledge`} dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Hubspot/>
            </ListItemIcon>
            <ListItemText
              primary={t('Graph')}
              secondary={t('Targeting knowledge')}
              classes={{ root: classes.listText }}
            />
          </MenuItem>
        </MenuList>
        <Divider/>
        <MenuList component='nav'>
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/compare`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/compare` } dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Compare/>
            </ListItemIcon>
            <ListItemText
              primary={t('Compare')}
              secondary={t('Threats targeting')}
              classes={{ root: classes.listText }}
            />
          </MenuItem>
          <MenuItem style={{ padding: '20px 10px 20px 10px' }} component={Link} disabled={!threatId} to={`/dashboard/explore/victimology/${threatId}/knowledge`} selected={location.pathname === `/dashboard/explore/victimology/${threatId}/knowledge`} dense={false}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Hubspot/>
            </ListItemIcon>
            <ListItemText
              primary={t('Graph')}
              secondary={t('Targeting knowledge')}
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
