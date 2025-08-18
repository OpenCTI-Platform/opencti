import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import { useInvestigationState } from './utils/useInvestigationState';
import { InvestigationAddStixCoreObjecstLineDummy, InvestigationAddStixCoreObjectsLine } from './InvestigationAddStixCoreObjectsLine';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { numberFormat } from '../../../../utils/Number';

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

const investigationAddStixCoreObjectsLinesRelationAddMutation = graphql`
  mutation InvestigationAddStixCoreObjectsLinesRelationAddMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const investigationAddStixCoreObjectsLinesRelationDeleteMutation = graphql`
  mutation InvestigationAddStixCoreObjectsLinesRelationDeleteMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const InvestigationAddStixCoreObjectsLinesInvestigation = (props) => {
  const {
    workspaceId,
    onAdd,
    onDelete,
    initialLoading,
    relay,
    dataColumns,
    containerRef,
    workspaceStixCoreObjects,
    setNumberOfElements,
  } = props;

  const { addInvestigationOpInStack } = useInvestigationState(workspaceId);

  const [addedStixCoreObjects, setAddedStixCoreObjects] = useState(R.indexBy(
    R.prop('id'),
    (workspaceStixCoreObjects || []).map((n) => n.node),
  ));

  useEffect(() => {
    const numberOfElements = workspaceStixCoreObjects?.length ?? 0;
    setNumberOfElements(numberFormat(numberOfElements));
  }, [workspaceStixCoreObjects]);

  const toggleStixCoreObject = (stixCoreObject) => {
    const alreadyAdded = stixCoreObject.id in addedStixCoreObjects;
    if (alreadyAdded) {
      addInvestigationOpInStack({
        type: 'remove',
        dateTime: new Date().getTime(),
        objects: [stixCoreObject],
      });
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
          setAddedStixCoreObjects(R.dissoc(
            stixCoreObject.id,
            addedStixCoreObjects,
          ));
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
      addInvestigationOpInStack({
        type: 'add',
        dateTime: new Date().getTime(),
        objectsIds: [stixCoreObject.id],
      });
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationAddMutation,
        variables: {
          id: workspaceId,
          input,
        },
        onCompleted: () => {
          setAddedStixCoreObjects({
            ...addedStixCoreObjects,
            [stixCoreObject.id]: stixCoreObject,
          });
          if (typeof onAdd === 'function') {
            onAdd(stixCoreObject);
          }
        },
      });
    }
  };

  return (
    <ListLinesContent
      initialLoading={initialLoading}
      loadMore={relay.loadMore}
      hasMore={relay.hasMore}
      isLoading={relay.isLoading}
      dataList={R.pathOr([], ['stixCoreObjects', 'edges'], props.data)}
      globalCount={R.pathOr(
        nbOfRowsToLoad,
        ['stixCoreObjects', 'pageInfo', 'globalCount'],
        props.data,
      )}
      LineComponent={<InvestigationAddStixCoreObjectsLine />}
      DummyLineComponent={<InvestigationAddStixCoreObjecstLineDummy />}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      addedElements={addedStixCoreObjects}
      onToggleEntity={toggleStixCoreObject}
      disableExport={true}
      containerRef={containerRef}
    />
  );
};

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
    $count: Int!
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
