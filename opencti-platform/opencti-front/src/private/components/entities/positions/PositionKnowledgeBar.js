import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
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

class PositionKnowledgeBar extends Component {
  render() {
    const { t, location, classes, positionId } = this.props;
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
            to={`/dashboard/entities/positions/${positionId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/entities/positions/${positionId}/knowledge/overview`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Gauge />
            </ListItemIcon>
            <ListItemText
              primary={t('Overview')}
              secondary={t('Synthesis of knowledge')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/positions/${positionId}/knowledge/threats`}
            selected={
              location.pathname
              === `/dashboard/entities/positions/${positionId}/knowledge/threats`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <TargetVariant />
            </ListItemIcon>
            <ListItemText
              primary={t('Threats')}
              secondary={t('Targeting this position')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

PositionKnowledgeBar.propTypes = {
  positionId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(PositionKnowledgeBar);
