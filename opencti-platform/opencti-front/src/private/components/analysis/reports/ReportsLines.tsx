import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ReportLine, ReportLineDummy } from './ReportLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  ReportsLinesPaginationQuery,
  ReportsLinesPaginationQuery$variables,
} from './__generated__/ReportsLinesPaginationQuery.graphql';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import { ReportsLines_data$key } from './__generated__/ReportsLines_data.graphql';
import { ReportLine_node$data } from './__generated__/ReportLine_node.graphql';

const nbOfRowsToLoad = 50;

export const reportsLinesQuery = graphql`
    query ReportsLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: ReportsOrdering
        $orderMode: OrderingMode
        $filters: [ReportsFiltering]
    ) {
        ...ReportsLines_data
        @arguments(
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        )
    }
`;

const reportsLineFragment = graphql`
    fragment ReportsLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "ReportsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[ReportsFiltering]" }
    )
    @refetchable(queryName: "ReportsLinesRefetchQuery") {
        reports(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_reports") {
            edges {
                node {
                    id
                    name
                    published
                    createdBy {
                        ... on Identity {
                            id
                            name
                            entity_type
                        }
                    }
                    objectMarking {
                        edges {
                            node {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
                            }
                        }
                    }
                    creator {
                        id
                        name
                    }
                    ...ReportLine_node
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

interface ReportsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: ReportsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<ReportsLinesPaginationQuery>;
  selectedElements: Record<string, ReportLine_node$data>;
  deSelectedElements: Record<string, ReportLine_node$data>;
  onToggleEntity: (
    entity: ReportLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter,
  redirectionMode?: string,
}

const ReportsLines: FunctionComponent<
ReportsLinesProps
> = ({
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  paginationOptions,
  setNumberOfElements,
  queryRef,
  redirectionMode,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ReportsLinesPaginationQuery,
  ReportsLines_data$key>(
    {
      linesQuery: reportsLinesQuery,
      linesFragment: reportsLineFragment,
      queryRef,
      nodePath: ['reports', 'pageInfo', 'globalCount'],
      setNumberOfElements,
    },
  );

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.reports?.edges ?? []}
      globalCount={data?.reports?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={ReportLine}
      DummyLineComponent={ReportLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
      redirectionMode={redirectionMode}
    />
  );
};

export default ReportsLines;
