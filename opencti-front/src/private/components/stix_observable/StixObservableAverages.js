import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import ItemConfidenceLevel from '../../../components/ItemConfidenceLevel';
import ItemScore from '../../../components/ItemScore';

const styles = () => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class StixObservableAveragesComponent extends Component {
  render() {
    const { t, fld, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Averages of context relations')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Confidence level')}
          </Typography>
          <ItemConfidenceLevel level={2} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Scoring')}
          </Typography>
          <ItemScore score={74} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Expiration')}
          </Typography>
          {fld('2018-08-08')}
        </Paper>
      </div>
    );
  }
}

StixObservableAveragesComponent.propTypes = {
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const StixObservableAverages = createFragmentContainer(
  StixObservableAveragesComponent,
  {
    stixObservable: graphql`
      fragment StixObservableAverages_stixObservable on StixObservable {
        id
        observable_value
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableAverages);
