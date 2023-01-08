import React, { FunctionComponent } from 'react';
import {
  createPaginationContainer,
  graphql,
  RelayPaginationProp,
} from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  ExternalReferenceLine,
  ExternalReferenceLineDummy,
} from './ExternalReferenceLine';
import { ExternalReferencesLines_data$data } from './__generated__/ExternalReferencesLines_data.graphql';
import { ExternalReferencesLinesPaginationQuery$variables } from './__generated__/ExternalReferencesLinesPaginationQuery.graphql';
import { ExternalReferenceLine_node$data } from './__generated__/ExternalReferenceLine_node.graphql';
import { UseLocalStorage } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface ExternalReferencesLinesProps {
  initialLoading: boolean;
  setNumberOfElements: UseLocalStorage[2]['handleSetNumberOfElements'];
  dataColumns: {
    source_name: {
      label: string;
      width: string;
      isSortable: boolean;
    };
    external_id: {
      label: string;
      width: string;
      isSortable: boolean;
    };
    url: {
      label: string;
      width: string;
      isSortable: boolean;
    };
    creator: {
      label: string;
      width: string;
      isSortable: boolean;
    };
    created: {
      label: string;
      width: string;
      isSortable: boolean;
    };
  };
  relay: RelayPaginationProp;
  paginationOptions: ExternalReferencesLinesPaginationQuery$variables;
  data: ExternalReferencesLines_data$data;
  selectedElements: Record<string, ExternalReferenceLine_node$data>;
  deSelectedElements: Record<string, ExternalReferenceLine_node$data>;
  onToggleEntity: (
    entity: ExternalReferenceLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

const ExternalReferencesLines: FunctionComponent<
ExternalReferencesLinesProps
> = ({
  initialLoading,
  dataColumns,
  relay,
  paginationOptions,
  data,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  return (
    <ListLinesContent
      initialLoading={initialLoading}
      loadMore={relay.loadMore}
      hasMore={relay.hasMore}
      isLoading={relay.isLoading}
      dataList={data?.externalReferences?.edges ?? []}
      globalCount={
        data?.externalReferences?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={ExternalReferenceLine}
      DummyLineComponent={ExternalReferenceLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export const externalReferencesLinesQuery = graphql`
  query ExternalReferencesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
  ) {
    ...ExternalReferencesLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  ExternalReferencesLines,
  {
    data: graphql`
      fragment ExternalReferencesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "ExternalReferencesOrdering"
          defaultValue: source_name
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        externalReferences(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_externalReferences") {
          edges {
            node {
              ...ExternalReferenceLine_node
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
      return props.data && props.data.externalReferences;
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
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: externalReferencesLinesQuery,
  },
);
