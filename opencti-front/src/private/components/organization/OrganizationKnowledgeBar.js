import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Drawer from '@material-ui/core/Drawer';
import { DeviceHub, Domain, Person } from '@material-ui/icons';
import { SourceFork, TargetVariant } from 'mdi-material-ui';
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

class OrganizationKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, organizationId,
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
              === `/dashboard/catalogs/organizations/${organizationId}/knowledge/overview`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/catalogs/organizations/${organizationId}/knowledge/overview`}
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
              === `/dashboard/catalogs/organizations/${organizationId}/knowledge/sectors`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/catalogs/organizations/${organizationId}/knowledge/sectors`}
        >
          <div className={classes.icon}>
            <Domain fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Sectors')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Related to this organization')}
            </span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/catalogs/organizations/${organizationId}/knowledge/persons`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/catalogs/organizations/${organizationId}/knowledge/persons`}
        >
          <div className={classes.icon}>
            <Person fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Persons')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Belonging to this organization')}
            </span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/catalogs/organizations/${organizationId}/knowledge/threats`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/catalogs/organizations/${organizationId}/knowledge/threats`}
        >
          <div className={classes.icon}>
            <TargetVariant fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Threats')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Targeting this organization')}
            </span>
          </div>
        </Paper>
        <Paper
          classes={{
            root:
              location.pathname
              === `/dashboard/catalogs/organizations/${organizationId}/knowledge/entities`
                ? classes.paperActive
                : classes.paper,
          }}
          elevation={2}
          component={Link}
          to={`/dashboard/catalogs/organizations/${organizationId}/knowledge/entities`}
        >
          <div className={classes.icon}>
            <SourceFork fontSize="default" />
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Entities')}</span>
            <br />
            <span className={classes.subtitle}>
              {t('Related to this organization')}
            </span>
          </div>
        </Paper>
      </Drawer>
    );
  }
}

OrganizationKnowledgeBar.propTypes = {
  organizationId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(OrganizationKnowledgeBar);
