import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(1),
    padding: '0 5px 0 5px',
    minHeight: 20,
    textTransform: 'none',
  },
});

class TopMenuSearch extends Component {
  render() {
    const { t, classes, location } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/import"
          variant={
            location.pathname === '/dashboard/import' ? 'contained' : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/import' ? 'secondary' : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Data import')}
        </Button>
      </div>
    );
  }
}

TopMenuSearch.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuSearch);
