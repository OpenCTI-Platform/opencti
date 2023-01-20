/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import ChevronRightIcon from '@material-ui/icons/ChevronRight';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '4px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  button: {
    marginRight: theme.spacing(1),
    padding: '4px 25px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuDataResponsiblePartiesEntities extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/data/entities/responsible_parties"
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Responsible Parties')}
        </Button>
        <ChevronRightIcon
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to="/data/entities/responsible_parties"
          variant={
            location.pathname.includes('/data/entities/responsible_parties')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/data/entities/responsible_parties')
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Entities')}
        </Button>
        <Button
          component={Link}
          to="/data/data_source"
          variant={
            location.pathname.includes('/data/data_source')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/data/data_source')
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Data Sources')}
        </Button>
      </div>
    );
  }
}

TopMenuDataResponsiblePartiesEntities.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuDataResponsiblePartiesEntities);
