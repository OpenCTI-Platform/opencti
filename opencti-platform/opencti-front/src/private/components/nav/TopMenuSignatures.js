import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import windowDimensions from 'react-window-dimensions';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { HexagonOutline, ShieldSearch } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuSignatures extends Component {
  render() {
    const {
      t, location, classes, width,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/signatures/observables"
          variant={
            location.pathname.includes('/dashboard/signatures/observables')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/signatures/observables')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <HexagonOutline
            className={width > 950 ? classes.icon : ''}
            fontSize="small"
          />
          {width > 950 ? t('Observables') : ''}
        </Button>
        <Button
          component={Link}
          to="/dashboard/signatures/indicators"
          variant={
            location.pathname.includes('/dashboard/signatures/indicators')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/signatures/indicators')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <ShieldSearch
            className={width > 950 ? classes.icon : ''}
            fontSize="small"
          />
          {width > 950 ? t('Indicators') : ''}
        </Button>
      </div>
    );
  }
}

TopMenuSignatures.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  width: PropTypes.number,
};

export default compose(
  inject18n,
  withRouter,
  windowDimensions(),
  withStyles(styles),
)(TopMenuSignatures);
