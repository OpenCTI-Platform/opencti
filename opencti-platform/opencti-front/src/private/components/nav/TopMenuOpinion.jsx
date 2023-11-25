import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuOpinion extends Component {
  render() {
    const { t, location, id: opinionId, classes } = this.props;
    return (
      <>
        <Button
          component={Link}
          to={`/dashboard/analyses/opinions/${opinionId}`}
          variant={
            location.pathname === `/dashboard/analyses/opinions/${opinionId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
          disabled={!opinionId}
        >
          {t('Opinion')}
        </Button>
      </>
    );
  }
}

TopMenuOpinion.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  id: PropTypes.string,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuOpinion);
