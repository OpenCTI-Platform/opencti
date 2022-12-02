import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '4px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
});

class TopMenuRiskAssessment extends Component {
  render() {
    const { t, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/activities/risk_assessment/risks"
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Risks')}
        </Button>
      </div>
    );
  }
}

TopMenuRiskAssessment.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuRiskAssessment);
