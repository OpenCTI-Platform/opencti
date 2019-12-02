import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Flag } from '@material-ui/icons';
import { Gauge, TargetVariant } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  drawer: {
    minHeight: '100vh',
    width: 260,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
    backgroundColor: theme.palette.background.navLight,
  },
  item: {
    padding: '0 0 0 15px',
  },
  toolbar: theme.mixins.toolbar,
});

class RegionKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, regionId,
    } = this.props;
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
            to={`/dashboard/entities/regions/${regionId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/entities/regions/${regionId}/knowledge/overview`
            }
            dense={false}
            classes={{ root: classes.item }}
          >

            <ListItemIcon>
              <Gauge />
            </ListItemIcon>
            <ListItemText primary={t('Overview')} secondary={t('Synthesis of knowledge')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/regions/${regionId}/knowledge/countries`}
            selected={
              location.pathname
              === `/dashboard/entities/regions/${regionId}/knowledge/countries`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Flag />
            </ListItemIcon>
            <ListItemText
              primary={t('Countries')}
              secondary={t('Localized in this region')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/regions/${regionId}/knowledge/threats`}
            selected={
              location.pathname
              === `/dashboard/entities/regions/${regionId}/knowledge/threats`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <TargetVariant />
            </ListItemIcon>
            <ListItemText
              primary={t('Threats')}
              secondary={t('Targeting this region')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

RegionKnowledgeBar.propTypes = {
  regionId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(RegionKnowledgeBar);
