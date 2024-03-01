import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import { InvestigationAddStixCoreObjecstLineDummy, InvestigationAddStixCoreObjectsLine } from './InvestigationAddStixCoreObjectsLine';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { setNumberOfElements } from '../../../../utils/Number';

const styles = (theme) => ({
  investigation: {
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
    width: '100M',
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

const nbOfRowsToLoad = 50;

export const investigationAddStixCoreObjectsLinesRelationAddMutation = graphql`
    mutation InvestigationAddStixCoreObjectsLinesRelationAddMutation(
        $id: ID!
        $input: [EditInput!]!
    ) {
        workspaceFieldPatch(id: $id, input: $input) {
            id
        }
    }
`;

export const investigationAddStixCoreObjectsLinesRelationDeleteMutation = graphql`
    mutation InvestigationAddStixCoreObjectsLinesRelationDeleteMutation(
        $id: ID!
        $input: [EditInput!]!
    ) {
        workspaceFieldPatch(id: $id, input: $input) {
            id
        }
    }
`;

export const investigationAddStixCoreObjectsLinesRelationsDeleteMutation = graphql`
    mutation InvestigationAddStixCoreObjectsLinesRelationsDeleteMutation(
        $id: ID!
        $input: [EditInput!]!
    ) {
        workspaceFieldPatch(id: $id, input: $input) {
            id
        }
    }
`;

class InvestigationAddStixCoreObjectsLinesInvestigation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      expandedPanels: {},
      addedStixCoreObjects: R.indexBy(
        R.prop('id'),
        (props.workspaceStixCoreObjects || []).map((n) => n.node),
      ),
    };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixCoreObjects',
      this.props.setNumberOfElements.bind(this),
    );
  }

  toggleStixCoreObject(stixCoreObject) {
    const { workspaceId, onAdd, onDelete } = this.props;
    const { addedStixCoreObjects } = this.state;
    const alreadyAdded = stixCoreObject.id in addedStixCoreObjects;
    if (alreadyAdded) {
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationDeleteMutation,
        variables: {
          id: workspaceId,
          input: {
            key: 'investigated_entities_ids',
            operation: 'remove',
            value: stixCoreObject.id,
          },
        },
        onCompleted: () => {
          this.setState({
            addedStixCoreObjects: R.dissoc(
              stixCoreObject.id,
              this.state.addedStixCoreObjects,
            ),
          });
          if (typeof onDelete === 'function') {
            onDelete(stixCoreObject);
          }
        },
      });
    } else {
      const input = {
        key: 'investigated_entities_ids',
        operation: 'add',
        value: stixCoreObject.id,
      };
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationAddMutation,
        variables: {
          id: workspaceId,
          input,
        },
        onCompleted: () => {
          this.setState({
            addedStixCoreObjects: {
              ...this.state.addedStixCoreObjects,
              [stixCoreObject.id]: stixCoreObject,
            },
          });
          if (typeof onAdd === 'function') {
            onAdd(stixCoreObject);
          }
        },
      });
    }
  }

  render() {
    const { initialLoading, relay, dataColumns, containerRef } = this.props;
    const { addedStixCoreObjects } = this.state;
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
        LineComponent={<InvestigationAddStixCoreObjectsLine />}
        DummyLineComponent={<InvestigationAddStixCoreObjecstLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        addedElements={addedStixCoreObjects}
        onToggleEntity={this.toggleStixCoreObject.bind(this)}
        disableExport={true}
        containerRef={containerRef}
      />
    );
  }
}

InvestigationAddStixCoreObjectsLinesInvestigation.propTypes = {
  workspaceId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  workspaceStixCoreObjects: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
};

export const investigationAddStixCoreObjectsLinesQuery = graphql`
  query InvestigationAddStixCoreObjectsLinesQuery(
    $types: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...InvestigationAddStixCoreObjectsLines_data
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

const InvestigationAddStixCoreObjectsLines = createPaginationContainer(
  InvestigationAddStixCoreObjectsLinesInvestigation,
  {
    data: graphql`
      fragment InvestigationAddStixCoreObjectsLines_data on Query
      @argumentDefinitions(
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
      ) {
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
              entity_type
              parent_types
              numberOfConnectedElement
              created_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
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
              ...InvestigationAddStixCoreObjectsLine_node
            }
          }
          pageInfo {
            endCursor
            hasNextPage
            globalCount
          }
        }
      }
    `,
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
    query: investigationAddStixCoreObjectsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(InvestigationAddStixCoreObjectsLines);
