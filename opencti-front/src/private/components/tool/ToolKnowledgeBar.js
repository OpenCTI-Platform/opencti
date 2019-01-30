import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Drawer from '@material-ui/core/Drawer';
import { DeviceHub } from '@material-ui/icons';
import {
  ChessKnight,
  Fire,
  Diamond,
  Biohazard,
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

class ToolKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, toolId,
    } = this.props;
    return (
      <Drawer variant='permanent' anchor='right' classes={{ paper: classes.drawerPaper }}>
        <div className={classes.toolbar}/>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/tools/${toolId}/knowledge/overview` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/tools/${toolId}/knowledge/overview`}>
          <div className={classes.icon}>
            <DeviceHub fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Overview')}</span><br />
            <span className={classes.subtitle}>{t('Knowledge graph')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/tools/${toolId}/knowledge/intrusion_sets` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/tools/${toolId}/knowledge/intrusion_sets`}>
          <div className={classes.icon}>
            <Diamond fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Intrusion sets')}</span><br />
            <span className={classes.subtitle}>{t('Using this tool')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/tools/${toolId}/knowledge/campaigns` ? classes.paperActive : classes.paper }} elevation={2} component={Link} to={`/dashboard/catalogs/tools/${toolId}/knowledge/campaigns`}>
          <div className={classes.icon}>
            <ChessKnight fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Campaigns')}</span><br />
            <span className={classes.subtitle}>{t('Using this tool')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/tools/${toolId}/knowledge/incidents` ? classes.paperActive : classes.paper}} elevation={2} component={Link} to={`/dashboard/catalogs/tools/${toolId}/knowledge/incidents`}>
          <div className={classes.icon}>
            <Fire fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Incidents')}</span><br />
            <span className={classes.subtitle}>{t('Using this tool')}</span>
          </div>
        </Paper>
        <Paper classes={{ root: location.pathname === `/dashboard/catalogs/tools/${toolId}/knowledge/malwares` ? classes.paperActive : classes.paper}} elevation={2} component={Link} to={`/dashboard/catalogs/tools/${toolId}/knowledge/malwares`}>
          <div className={classes.icon}>
            <Biohazard fontSize='default'/>
          </div>
          <div className={classes.content}>
            <span className={classes.title}>{t('Malwares')}</span><br />
            <span className={classes.subtitle}>{t('Using this tool')}</span>
          </div>
        </Paper>
      </Drawer>
    );
  }
}

ToolKnowledgeBar.propTypes = {
  toolId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ToolKnowledgeBar);
