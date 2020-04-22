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
import { BugReport } from '@material-ui/icons';
import {
  ChessKnight,
  LockPattern,
  Application,
  Target,
  Fire,
  DiamondOutline,
  Biohazard,
  Gauge,
} from 'mdi-material-ui';
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

class ThreatActorKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, threatActorId,
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
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/overview`
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
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/victimology`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/victimology`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Target />
            </ListItemIcon>
            <ListItemText
              primary={t('Victimology')}
              secondary={t('Targeted by this actor')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/intrusion_sets`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/intrusion_sets`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <DiamondOutline />
            </ListItemIcon>
            <ListItemText
              primary={t('Intrusion sets')}
              secondary={t('Attributed to this actor')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/campaigns`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/campaigns`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <ChessKnight />
            </ListItemIcon>
            <ListItemText
              primary={t('Campaigns')}
              secondary={t('Attributed to this actor')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/incidents`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/incidents`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Fire />
            </ListItemIcon>
            <ListItemText
              primary={t('Incidents')}
              secondary={t('Attributed to this actor')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/malwares`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/malwares`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Biohazard />
            </ListItemIcon>
            <ListItemText
              primary={t('Malwares')}
              secondary={t('Used by this actor')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/ttp`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/ttp`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <LockPattern />
            </ListItemIcon>
            <ListItemText
              primary={t('Techniques')}
              secondary={t('Used by this actor')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/tools`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/tools`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Application />
            </ListItemIcon>
            <ListItemText
              primary={t('Tools')}
              secondary={t('Used by this actor')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/vulnerabilities`}
            selected={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/knowledge/vulnerabilities`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <BugReport />
            </ListItemIcon>
            <ListItemText
              primary={t('Vulnerabilities')}
              secondary={t('Targeted by this actor')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

ThreatActorKnowledgeBar.propTypes = {
  threatActorId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ThreatActorKnowledgeBar);
