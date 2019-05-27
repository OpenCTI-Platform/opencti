import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Drawer from '@material-ui/core/Drawer';
import { DeviceHub, AccountBalance } from '@material-ui/icons';
import {
  ChessKnight, Biohazard, Fire, Diamond,
} from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 260,
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: '#303030',
    padding: 0,
  },
  paper: {
    width: '90%',
    height: 60,
    margin: '0 auto',
    marginTop: 15,
    padding: 10,
    transition: 'all 0.3s',
    borderRadius: 6,
    '&:hover': {
      backgroundColor: theme.palette.background.paperLight,
    },
  },
  paperActive: {
    width: '90%',
    height: 60,
    margin: '0 auto',
    marginTop: 15,
    padding: 10,
    backgroundColor: theme.palette.background.paperLight,
    borderRadius: 6,
  },
  toolbar: theme.mixins.toolbar,
  icon: {
    float: 'left',
    paddingTop: 7,
  },
  content: {
    float: 'left',
    padding: '0 0 0 16px',
  },
  title: {
    fontSize: 15,
  },
  subtitle: {
    fontSize: 12,
    color: '#d3d3d3',
  },
});

class SectorKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, sectorId,
    } = this.props;
    return (
      <Drawer
        variant="permanent"
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
      >
        <div className={classes.toolbar} />
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/knowledge/sectors/${sectorId}/knowledge/overview`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/knowledge/sectors/${sectorId}/knowledge/overview`}
        >
          <div className={classes.icon}>
            <DeviceHub fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Overview')}</span>
            <br />
            <span className={classes.subtitle}>{t('Knowledge graph')}</span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/knowledge/sectors/${sectorId}/knowledge/organizations`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/knowledge/sectors/${sectorId}/knowledge/organizations`}
        >
          <div className={classes.icon}>
            <AccountBalance fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Organizations')}</span>
            <br />
            <span className={classes.subtitle}>{t('Part of this sector')}</span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/knowledge/sectors/${sectorId}/knowledge/intrusion_sets`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/knowledge/sectors/${sectorId}/knowledge/intrusion_sets`}
        >
          <div className={classes.icon}>
            <Diamond fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Intrusion sets')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Targeting this sector')}
            </span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/knowledge/sectors/${sectorId}/knowledge/campaigns`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/knowledge/sectors/${sectorId}/knowledge/campaigns`}
        >
          <div className={classes.icon}>
            <ChessKnight fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Campaigns')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Targeting this sector')}
            </span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/knowledge/sectors/${sectorId}/knowledge/incidents`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/knowledge/sectors/${sectorId}/knowledge/incidents`}
        >
          <div className={classes.icon}>
            <Fire fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Incidents')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Affecting this sector')}
            </span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/knowledge/sectors/${sectorId}/knowledge/malwares`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/knowledge/sectors/${sectorId}/knowledge/malwares`}
        >
          <div className={classes.icon}>
            <Biohazard fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Malwares')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Targeting this sector')}
            </span>
          </div>
        </Paper>
      </Drawer>
    );
  }
}

SectorKnowledgeBar.propTypes = {
  sectorId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SectorKnowledgeBar);
