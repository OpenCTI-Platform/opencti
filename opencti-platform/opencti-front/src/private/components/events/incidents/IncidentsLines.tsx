import React, { FunctionComponent } from 'react';
import { PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IncidentLine, IncidentLineDummy } from './IncidentLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { IncidentsCardsAndLinesFragment, incidentsCardsAndLinesPaginationQuery } from './IncidentsCards';
import {
  IncidentsCardsAndLinesPaginationQuery,
  IncidentsCardsAndLinesPaginationQuery$variables,
} from './__generated__/IncidentsCardsAndLinesPaginationQuery.graphql';
import { IncidentsCardsAndLines_data$key } from './__generated__/IncidentsCardsAndLines_data.graphql';

const nbOfRowsToLoad = 50;

interface IncidentsLinesProps {
  paginationOptions?: IncidentsCardsAndLinesPaginationQuery$variables,
  dataColumns: DataColumns,
  queryRef: PreloadedQuery<IncidentsCardsAndLinesPaginationQuery>,
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'],
  onLabelClick: HandleAddFilter
}
const IncidentsLines: FunctionComponent<IncidentsLinesProps> = ({ setNumberOfElements, dataColumns, queryRef, paginationOptions, onLabelClick }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<IncidentsCardsAndLinesPaginationQuery, IncidentsCardsAndLines_data$key>({
    linesQuery: incidentsCardsAndLinesPaginationQuery,
    linesFragment: IncidentsCardsAndLinesFragment,
    queryRef,
    nodePath: ['incidents', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.incidents?.edges ?? []}
      globalCount={data?.incidents?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={IncidentLine}
      DummyLineComponent={IncidentLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      paginationOptions={paginationOptions}
    />
  );
};
export default IncidentsLines;
