import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import type { Filters } from '../../../../../components/list_lines';
import { UseLocalStorageHelpers, usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import ListLines from '../../../../../components/list_lines/ListLines';
import usePreloadedPaginationFragment from '../../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../../components/list_lines';
import {
  AlertingPaginationQuery,
  AlertingPaginationQuery$variables,
} from './__generated__/AlertingPaginationQuery.graphql';
import AlertCreation from './AlertCreation';
import ActivityMenu from '../../ActivityMenu';
import { AlertingLines_data$key } from './__generated__/AlertingLines_data.graphql';
import { AlertingLineComponent, AlertingLineDummy } from './AlertingLine';
import { Theme } from '../../../../../components/Theme';

export const LOCAL_STORAGE_KEY_DATA_SOURCES = 'view-alerting';
const nbOfRowsToLoad = 50;

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

export const alertingQuery = graphql`
    query AlertingPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: TriggersOrdering
        $orderMode: OrderingMode
        $filters: [TriggerActivityFiltering!]
    ) {
        ...AlertingLines_data
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

const alertingFragment = graphql`
    fragment AlertingLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "TriggersOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[TriggerActivityFiltering!]" }
    )
    @refetchable(queryName: "AlertingLinesRefetchQuery") {
        triggersActivity(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_triggersActivity") {
            edges {
                node {
                    id
                    name
                    description
                    ...AlertingLine_node
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

interface AlertingLinesProps {
  queryRef: PreloadedQuery<AlertingPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: AlertingPaginationQuery$variables;
  setNumberOfElements?: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick?: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
}

const AlertingLines: FunctionComponent<AlertingLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  AlertingPaginationQuery,
  AlertingLines_data$key
  >({
    linesQuery: alertingQuery,
    linesFragment: alertingFragment,
    queryRef,
    nodePath: ['triggersActivity', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
        <ListLinesContent
            initialLoading={!data}
            isLoading={isLoadingMore}
            loadMore={loadMore}
            hasMore={hasMore}
            dataList={data?.triggersActivity?.edges ?? []}
            globalCount={data?.triggersActivity?.pageInfo?.globalCount ?? nbOfRowsToLoad}
            LineComponent={AlertingLineComponent}
            DummyLineComponent={AlertingLineDummy}
            dataColumns={dataColumns}
            nbOfRowsToLoad={nbOfRowsToLoad}
            paginationOptions={paginationOptions}
            onLabelClick={onLabelClick}
        />
  );
};

const Alerting: FunctionComponent = () => {
  const classes = useStyles();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<AlertingPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_DATA_SOURCES,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      filters: {} as Filters,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );
  const renderLines = () => {
    const { searchTerm, sortBy, orderAsc, filters, numberOfElements } = viewStorage;
    const dataColumns = {
      trigger_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '15%',
        isSortable: true,
      },
      outcomes: {
        label: 'Notification',
        width: '20%',
        isSortable: true,
      },
      event_types: {
        label: 'Triggering on',
        width: '20%',
        isSortable: false,
      },
      filters: {
        label: 'Details',
        width: '30%',
        isSortable: false,
      },
    };
    const queryRef = useQueryLoading<AlertingPaginationQuery>(alertingQuery, paginationOptions);
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchFilter={helpers.handleSwitchFilter}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'trigger_type',
          'created_start_date',
          'created_end_date',
        ]}>
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array.from(Array(20).keys()).map((idx) => (
                  <AlertingLineDummy
                    key={`AlertingLineDummy-${idx}`}
                    dataColumns={dataColumns}
                  />
                ))}
              </>
            }>
            <AlertingLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              onLabelClick={helpers.handleAddFilter}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <div className={classes.container}>
      <ActivityMenu />
      {renderLines()}
      <AlertCreation paginationOptions={paginationOptions} />
    </div>
  );
};

export default Alerting;
