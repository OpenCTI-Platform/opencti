import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLineDummy,
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLine,
} from './StixCoreRelationshipCreationFromEntityStixCoreObjectsLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

const styles = (theme) => ({
  container: {
    padding: '20px 0 20px 0',
  },
  heading: {
    fontSize: theme.typography.pxToRem(15),
    flexBasis: '33.33%',
    flexShrink: 0,
  },
  secondaryHeading: {
    fontSize: theme.typography.pxToRem(15),
    color: theme.palette.text.secondary,
  },
  expansionPanelContent: {
    padding: 0,
  },
  list: {
    width: '100%',
  },
  listItem: {
    width: '100%',
  },
  icon: {
    color: theme.palette.primary.main,
  },
  tooltip: {
    maxWidth: '80%',
    lineHeight: 2,
    padding: 10,
    backgroundColor: '#323232',
  },
});

class StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesComponent extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixCoreObjects',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      containerRef,
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={R.pathOr([], ['stixCoreObjects', 'edges'], this.props.data)}
        globalCount={R.pathOr(
          nbOfRowsToLoad,
          ['stixCoreObjects', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={
          <StixCoreRelationshipCreationFromEntityStixCoreObjectsLine />
        }
        DummyLineComponent={
          <StixCoreRelationshipCreationFromEntityStixCoreObjectsLineDummy />
        }
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity.bind(this)}
        disableExport={true}
        containerRef={containerRef}
      />
    );
  }
}

StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesComponent.propTypes = {
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  containerRef: PropTypes.object,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery = graphql`
  query StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data
      @arguments(
        types: $types
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export const stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment= graphql`
  fragment StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesRefetchQuery") {
    stixCoreObjects(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCoreObjects") {
      edges {
        node {
          id
          standard_id
          entity_type
          created_at
          createdBy {
            ... on Identity {
              name
            }
          }
          creators {
            id
            name
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;
const StixCoreRelationshipCreationFromEntityStixCoreObjectsLines = createPaginationContainer(
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesComponent,
  {
    data: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreObjects;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipCreationFromEntityStixCoreObjectsLines);
