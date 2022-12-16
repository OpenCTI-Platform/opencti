import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { createPaginationContainer } from 'react-relay';
import inject18n from '../../../../components/i18n';
import RiskObservationLine from './RiskObservationLine';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: 0,
    position: 'relative',
  },
  observationList: {
    marginBottom: 0,
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
  observationMain: {
    display: 'grid',
    gridTemplateColumns: '90% 10%',
    marginBottom: '10px',
  },

});

class RiskObservationLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
    };
  }

  render() {
    const { risk, history } = this.props;
    const RelatedObservations = R.pathOr([], ['related_observations', 'edges'], risk);
    return (
      <div>
        {RelatedObservations.map((observation) => (
          <RiskObservationLine
            key={observation.node.id}
            observationId={observation.node.id}
            observation={observation}
            history={history}
          />
        ))}
      </div>
    );
  }
}

RiskObservationLinesContainer.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  fd: PropTypes.func,
  relay: PropTypes.object,
  history: PropTypes.object,
};

export const riskObservationLinesQuery = graphql`
  query RiskObservationLinesPaginationQuery($id: ID!, $first: Int, $offset: Int) {
    risk(id: $id){
      id
      ...RiskObservationLines_risk
      @arguments(
        count: $first
        offset: $offset
      )
    }
  }
`;

export const RiskObservationLinesContainerComponent = createPaginationContainer(
  RiskObservationLinesContainer,
  {
    risk: graphql`
      fragment RiskObservationLines_risk on Risk
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 5 }
        offset: { type: "Int", defaultValue: 0 }
      ) {
        related_observations (
          first: $count,
          offset: $offset
          ) @connection(key: "Pagination_related_observations"){
          edges {
            node {
              id
              entity_type
              collected
              description
              name
              description
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.related_observations;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables({ count, cursor }, fragmentVariables) {
      return {
        first: fragmentVariables.first,
        offset: fragmentVariables.offset,
        count,
        cursor,
      };
    },
    query: riskObservationLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RiskObservationLinesContainerComponent);
