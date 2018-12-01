import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { Public, Domain } from '@material-ui/icons';
import { Radioactive, Diamond, Fire, ChessKnight } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  button: {
    marginRight: theme.spacing.unit * 2,
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing.unit,
  },
});

class TopMenuKnowledge extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button component={Link} to='/dashboard/knowledge' variant={location.pathname === '/dashboard/knowledge' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/knowledge' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Public className={classes.icon} fontSize='small'/>
          {t('Threat actors')}
        </Button>
        <Button component={Link} to='/dashboard/knowledge/sectors' variant={location.pathname === '/dashboard/knowledge/sectors' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/knowledge/sectors' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Domain className={classes.icon} fontSize='small'/>
          {t('Sectors')}
        </Button>
        <Button component={Link} to='/dashboard/knowledge/intrusion_sets' variant={location.pathname === '/dashboard/knowledge/intrusion_sets' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/knowledge/intrusion_sets' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Diamond className={classes.icon} fontSize='small'/>
          {t('Intrusion sets')}
        </Button>
        <Button component={Link} to='/dashboard/knowledge/campaigns' variant={location.pathname === '/dashboard/knowledge/campaigns' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/knowledge/campaigns' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <ChessKnight className={classes.icon} fontSize='small'/>
          {t('Campaigns')}
        </Button>
        <Button component={Link} to='/dashboard/knowledge/incidents' variant={location.pathname === '/dashboard/knowledge/incidents' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/knowledge/incidents' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Fire className={classes.icon} fontSize='small'/>
          {t('Incidents')}
        </Button>
        <Button component={Link} to='/dashboard/knowledge/malwares' variant={location.pathname === '/dashboard/knowledge/malwares' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/knowledge/malwares' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Radioactive className={classes.icon} fontSize='small'/>
          {t('Malwares')}
        </Button>
      </div>
    );
  }
}

TopMenuKnowledge.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuKnowledge);
