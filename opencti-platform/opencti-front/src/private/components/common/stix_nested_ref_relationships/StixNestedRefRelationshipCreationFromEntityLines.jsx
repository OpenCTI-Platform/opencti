import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { StixNestedRefRelationshipCreationFromEntityLine, StixNestedRefRelationshipCreationFromEntityLineDummy } from './StixNestedRefRelationshipCreationFromEntityLine';
import inject18n from '../../../../components/i18n';
import { setNumberOfElements } from '../../../../utils/Number';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

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

class StixNestedRefRelationshipCreationFromEntityLinesContainer extends Component {
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
      onToggleEntity,
      initialLoading,
      containerRef,
      selectAll,
      relay,
      data,
      dataColumns,
      selectedElements,
      deSelectedElements,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={data?.stixCoreObjects?.edges ?? []}
        globalCount={data?.stixCoreObjects?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        LineComponent={StixNestedRefRelationshipCreationFromEntityLine}
        DummyLineComponent={StixNestedRefRelationshipCreationFromEntityLineDummy}
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

StixNestedRefRelationshipCreationFromEntityLinesContainer.propTypes = {
  entityType: PropTypes.string,
  dataColumns: PropTypes.object,
  handleSelect: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  containerRef: PropTypes.object,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const stixNestedRefRelationshipCreationFromEntityLinesQuery = graphql`
  query StixNestedRefRelationshipCreationFromEntityLinesQuery(
    $search: String
    $types: [String]
    $count: Int
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixNestedRefRelationshipCreationFromEntityLines_data
    @arguments(
      search: $search
      types: $types
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const StixNestedRefRelationshipCreationFromEntityLines = createPaginationContainer(
  StixNestedRefRelationshipCreationFromEntityLinesContainer,
  {
    data: graphql`
      fragment StixNestedRefRelationshipCreationFromEntityLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          types: { type: "[String]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
          orderMode: { type: "OrderingMode", defaultValue: asc }
          filters: { type: "FilterGroup" }
        ) {
          stixCoreObjects(
            search: $search
            types: $types
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
          ) @connection(key: "Pagination_stixCoreObjects") {
            edges {
              node {
                ...StixNestedRefRelationshipCreationFromEntityLine_node
              }
            }
          }
        }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCyberObservables;
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
    query: stixNestedRefRelationshipCreationFromEntityLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixNestedRefRelationshipCreationFromEntityLines);
