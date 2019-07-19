import React, { Component } from 'react';
import PropTypes from 'prop-types';
import moment from 'moment-timezone';
import { compose, mean } from 'ramda';
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
    const {
      t, fld, classes, stixObservable,
    } = this.props;
    const scores = stixObservable.stixRelations.edges.map(n => n.node.score);
    const expirations = stixObservable.stixRelations.edges.map(n => moment(n.node.expiration));
    const weights = stixObservable.stixRelations.edges.map(n => n.node.weight
    );
    const minExpiration = moment.min(expirations);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Averages of context relations')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Confidence level')}
          </Typography>
          <ItemConfidenceLevel level={Math.trunc(mean(weights))} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Score')}
          </Typography>
          <ItemScore score={Math.trunc(mean(scores))} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Expiration')}
          </Typography>
          {fld(minExpiration.format())}
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
      fragment StixObservableAverages_stixObservable on StixObservable
        @argumentDefinitions(relationType: { type: "String" }) {
        id
        stixRelations(relationType: $relationType) {
          edges {
            node {
              score
              expiration
              weight
            }
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableAverages);
