import React, { FunctionComponent } from 'react';
import { PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IncidentLine, IncidentLineDummy } from './IncidentLine';
import { DataColumns } from '../../../../components/list_lines';
import {
  HandleAddFilter,
  UseLocalStorageHelpers,
} from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  IncidentsCardsAndLinesFragment,
  incidentsCardsAndLinesPaginationQuery,
} from './IncidentsCards';
import {
  IncidentsCardsAndLinesPaginationQuery,
  IncidentsCardsAndLinesPaginationQuery$variables,
} from './__generated__/IncidentsCardsAndLinesPaginationQuery.graphql';
import { IncidentsCardsAndLines_data$key } from './__generated__/IncidentsCardsAndLines_data.graphql';
import { IncidentLine_node$data } from './__generated__/IncidentLine_node.graphql';

const nbOfRowsToLoad = 50;

interface IncidentsLinesProps {
  paginationOptions?: IncidentsCardsAndLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<IncidentsCardsAndLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
  selectedElements: Record<string, IncidentLine_node$data>;
  deSelectedElements: Record<string, IncidentLine_node$data>;
  onToggleEntity: (
    entity: IncidentLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}
const IncidentsLines: FunctionComponent<IncidentsLinesProps> = ({
  setNumberOfElements,
  dataColumns,
  queryRef,
  paginationOptions,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  IncidentsCardsAndLinesPaginationQuery,
  IncidentsCardsAndLines_data$key
  >({
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
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};
export default IncidentsLines;
