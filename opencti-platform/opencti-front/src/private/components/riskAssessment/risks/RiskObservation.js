import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
// import { QueryRenderer as QR } from 'react-relay';
// import DarkLightEnvironment from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
// import { QueryRenderer } from '../../../../relay/environment';
import RiskObservationLine from './RiskObservationLine';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '19px 0',
    overflowY: 'scroll',
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  buttonExpand: {
    position: 'absolute',
    bottom: 2,
    width: '100%',
    height: 25,
    backgroundColor: 'rgba(255, 255, 255, .2)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor: 'rgba(255, 255, 255, .5)',
    },
  },
});

class RiskObservation extends Component {
  render() {
    const {
      t,
      risk,
      classes,
      cyioCoreObjectId,
    } = this.props;
    const ObservationEdges = pathOr([], ['related_observations', 'edges'], risk);

    return (
      <div style={{ marginTop: '50px', height: '500px' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Observations')}
        </Typography>
        <div className="clearfix" />
        <Paper className={classes.paper} elevation={2}>
          {ObservationEdges.length > 0 ? (
            ObservationEdges.map((observationData) => (
              <RiskObservationLine
                key={observationData.node.id}
                data={observationData.node}
              />
            ))
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No Observations.')}
              </span>
            </div>
          )}
        </Paper>
      </div>
    );
  }
}

RiskObservation.propTypes = {
  risk: PropTypes.object,
  cyioCoreObjectId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const RiskObservationComponent = createFragmentContainer(
  RiskObservation,
  {
    risk: graphql`
      fragment RiskObservation_risk on POAMItem {
        id
        related_observations {
          edges {
            node {
              id
              name
              description
              methods
              collected
              expires
              observation_types
              relevant_evidence {
                id
                entity_type
                description
                href
              }
              subjects {
                subject_type
              }
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
)(RiskObservationComponent);
