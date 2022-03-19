import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { BugReport } from '@mui/icons-material';
import {
  LockPattern,
  Application,
  Target,
  Fire,
  SourcePull,
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

class CampaignKnowledgeBar extends Component {
  render() {
    const { t, location, classes, campaignId } = this.props;
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
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/overview`
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
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/attribution`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/attribution`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <SourcePull />
            </ListItemIcon>
            <ListItemText
              primary={t('Attribution')}
              secondary={t('Origins of this campaign')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/victimology`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/victimology`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Target />
            </ListItemIcon>
            <ListItemText
              primary={t('Victimology')}
              secondary={t('Targeted in this campaign')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/incidents`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/incidents`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Fire />
            </ListItemIcon>
            <ListItemText
              primary={t('Incidents')}
              secondary={t('Attributed to this campaign')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/malwares`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/malwares`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Biohazard />
            </ListItemIcon>
            <ListItemText
              primary={t('Malwares')}
              secondary={t('Used in this campaign')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/ttp`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/ttp`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <LockPattern />
            </ListItemIcon>
            <ListItemText
              primary={t('Techniques')}
              secondary={t('Used in this campaign')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/tools`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/tools`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Application />
            </ListItemIcon>
            <ListItemText
              primary={t('Tools')}
              secondary={t('Used in this campaign')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/vulnerabilities`}
            selected={
              location.pathname
              === `/dashboard/threats/campaigns/${campaignId}/knowledge/vulnerabilities`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <BugReport />
            </ListItemIcon>
            <ListItemText
              primary={t('Vulnerabilities')}
              secondary={t('Targeted in this campaign')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

CampaignKnowledgeBar.propTypes = {
  campaignId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CampaignKnowledgeBar);
