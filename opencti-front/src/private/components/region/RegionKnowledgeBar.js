import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Drawer from '@material-ui/core/Drawer';
import { DeviceHub, AccountBalance, Flag } from '@material-ui/icons';
import {
  SourcePull,
  TargetVariant,
  SourceFork,
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
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    transition: 'all 0.3s',
    borderRadius: 6,
    '&:hover': {
      backgroundColor: theme.palette.field.background,
    },
  },
  paperActive: {
    width: '90%',
    height: 60,
    margin: '0 auto',
    marginTop: 15,
    padding: 10,
    backgroundColor: theme.palette.field.background,
    color: theme.palette.text.main,
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

class RegionKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, regionId,
    } = this.props;
    return (
      <Drawer variant='permanent' anchor='right' classes={{ paper: classes.drawerPaper }}>
        <div className={classes.toolbar}/>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/regions/${regionId}/knowledge/overview` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/regions/${regionId}/knowledge/overview`}>
          <div className={classes.icon}>
            <DeviceHub fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Overview')}</span><br />
            <span className={classes.subtitle}>{t('Knowledge graph')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/regions/${regionId}/knowledge/countries` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/regions/${regionId}/knowledge/countries`}>
          <div className={classes.icon}>
            <Flag fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Countries')}</span><br />
            <span className={classes.subtitle}>{t('Localized in this region')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/regions/${regionId}/knowledge/threats` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/regions/${regionId}/knowledge/threats`}>
          <div className={classes.icon}>
            <TargetVariant fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Threats')}</span><br />
            <span className={classes.subtitle}>{t('Targeting this region')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/regions/${regionId}/knowledge/attribution` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/regions/${regionId}/knowledge/attribution`}>
          <div className={classes.icon}>
            <SourcePull fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Threats')}</span><br />
            <span className={classes.subtitle}>{t('Attributed to this region')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/regions/${regionId}/knowledge/entities` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/regions/${regionId}/knowledge/entities`}>
          <div className={classes.icon}>
            <SourceFork fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Entities')}</span><br />
            <span className={classes.subtitle}>{t('Related to this region')}</span>
          </div>
        </Paper>
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
