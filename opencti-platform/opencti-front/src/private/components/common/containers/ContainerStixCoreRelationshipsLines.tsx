import React, { FunctionComponent } from 'react';
import { PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import {
  StixCoreRelationshipsLinesPaginationQuery,
  StixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipsLinesPaginationQuery.graphql';
import { StixCoreRelationshipsLines_data$key } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipsLines_data.graphql';
import { stixCoreRelationshipsLinesFragment, stixCoreRelationshipsLinesQuery } from '@components/common/stix_core_relationships/StixCoreRelationships';
import ContainerStixCoreRelationshipsLine, { ContainerStixCoreRelationshipsLineDummy, ContainerRelationshipNode } from './ContainerStixCoreRelationshipsLine';

interface ContainerStixCoreRelationshipsLinesProps {
  dataColumns: DataColumns;
  paginationOptions: StixCoreRelationshipsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<StixCoreRelationshipsLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, ContainerRelationshipNode>;
  deSelectedElements: Record<string, ContainerRelationshipNode>;
  selectAll: boolean;
  onToggleEntity: (node: ContainerRelationshipNode, event: React.SyntheticEvent) => void;
}

const ContainerStixCoreRelationshipsLines: FunctionComponent<ContainerStixCoreRelationshipsLinesProps> = ({
  dataColumns,
  paginationOptions,
  queryRef,
  setNumberOfElements,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
    StixCoreRelationshipsLinesPaginationQuery,
    StixCoreRelationshipsLines_data$key
  >({
    linesQuery: stixCoreRelationshipsLinesQuery,
    linesFragment: stixCoreRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixCoreRelationships?.edges ?? []}
      globalCount={data?.stixCoreRelationships?.pageInfo?.globalCount ?? 50}
      LineComponent={ContainerStixCoreRelationshipsLine}
      DummyLineComponent={ContainerStixCoreRelationshipsLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={50}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default ContainerStixCoreRelationshipsLines;
