import React from 'react';
import { useParams } from 'react-router-dom';
import {
  SearchStixCoreObjectsLinesPaginationQuery,
  SearchStixCoreObjectsLinesPaginationQuery$variables,
} from '@components/__generated__/SearchStixCoreObjectsLinesPaginationQuery.graphql';
import { SearchStixCoreObjectsLines_data$data } from '@components/__generated__/SearchStixCoreObjectsLines_data.graphql';
import { searchLineFragment, searchStixCoreObjectsLinesFragment, searchStixCoreObjectsLinesQuery } from '@components/Search';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import useAuth from '../../utils/hooks/useAuth';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../utils/filters/filtersUtils';
import { decodeSearchKeyword } from '../../utils/SearchUtils';
import DataTable from '../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';
import { useFormatter } from '../../components/i18n';
import useConnectedDocumentModifier from '../../utils/hooks/useConnectedDocumentModifier';

export const NLQ_LOCAL_STORAGE_KEY = 'search';

const SearchNLQ = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('NLQ Results | Advanced Search'));
  const { keyword } = useParams() as { keyword: string };

  const searchTerm = decodeSearchKeyword(keyword);

  const initialValues = {
    sortBy: '_score',
    orderAsc: false,
    openExports: false,
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Core-Object']),
    },
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<SearchStixCoreObjectsLinesPaginationQuery$variables>(
    NLQ_LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
    search: searchTerm,
  } as unknown as SearchStixCoreObjectsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<SearchStixCoreObjectsLinesPaginationQuery>(
    searchStixCoreObjectsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns = {
    entity_type: {
      label: 'Type',
      percentWidth: 10,
      isSortable: true,
    },
    value: {
      label: 'Value',
      percentWidth: 22,
      isSortable: false,
    },
    createdBy: {
      label: 'Author',
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    creator: {
      label: 'Creator',
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      label: 'Labels',
      percentWidth: 16,
      isSortable: false,
    },
    created_at: {
      label: 'Platform creation date',
      percentWidth: 10,
      isSortable: true,
    },
    analyses: {
      label: 'Analyses',
      percentWidth: 8,
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
  };

  const preloadedPaginationOptions = {
    linesQuery: searchStixCoreObjectsLinesQuery,
    linesFragment: searchStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['globalSearch', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SearchStixCoreObjectsLinesPaginationQuery>;

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: SearchStixCoreObjectsLines_data$data) => data.globalSearch?.edges?.map((n) => n?.node)}
          storageKey={NLQ_LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          globalSearch={searchTerm}
          lineFragment={searchLineFragment}
          preloadedPaginationProps={preloadedPaginationOptions}
          exportContext={{ entity_type: 'Stix-Core-Object' }}
          availableEntityTypes={['Stix-Core-Object']}
          entityTypes={['Stix-Core-Object']}
          hideSearch={true}
        />
      )}
    </>
  );
};

export default SearchNLQ;
