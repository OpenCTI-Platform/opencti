import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

class StixCyberObservableAddIndicatorsLinesContainer extends Component {
  render() {
    const { data, stixCyberObservableIndicators, stixCyberObservable, indicatorParams } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={stixCyberObservable}
        relationshipType={'based-on'}
        availableDatas={data?.indicators}
        existingDatas={stixCyberObservableIndicators}
        updaterOptions={ { path: 'indicators', params: indicatorParams } }
        isRelationReversed={true}
      />
    );
  }
}

StixCyberObservableAddIndicatorsLinesContainer.propTypes = {
  stixCyberObservable: PropTypes.object,
  stixCyberObservableIndicators: PropTypes.array,
  data: PropTypes.object,
  indicatorParams: PropTypes.object,
};

export const stixCyberObservableAddIndicatorsLinesQuery = graphql`
  query StixCyberObservableAddIndicatorsLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCyberObservableAddIndicatorsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixCyberObservableAddIndicatorsLines = createPaginationContainer(
  StixCyberObservableAddIndicatorsLinesContainer,
  {
    data: graphql`
      fragment StixCyberObservableAddIndicatorsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "IndicatorsOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        indicators(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_indicators") {
          edges {
            node {
              id
              entity_type
              parent_types
              name
              pattern
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
      return props.data && props.data.indicators;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: stixCyberObservableAddIndicatorsLinesQuery,
  },
);

export default compose(inject18n)(StixCyberObservableAddIndicatorsLines);
