import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
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

class CityKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, cityId,
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
            to={`/dashboard/entities/cities/${cityId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/entities/cities/${cityId}/knowledge/overview`
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
            to={`/dashboard/entities/cities/${cityId}/knowledge/threats`}
            selected={
              location.pathname
              === `/dashboard/entities/cities/${cityId}/knowledge/threats`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <TargetVariant />
            </ListItemIcon>
            <ListItemText
              primary={t('Threats')}
              secondary={t('Targeting this city')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

CityKnowledgeBar.propTypes = {
  cityId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CityKnowledgeBar);
