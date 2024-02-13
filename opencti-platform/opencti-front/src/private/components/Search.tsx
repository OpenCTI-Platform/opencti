import React from 'react';
import { SearchStixCoreObjectLineDummy } from '@components/search/SearchStixCoreObjectLine';
import { SearchStixCoreObjectLine_node$data } from '@components/search/__generated__/SearchStixCoreObjectLine_node.graphql';
import {
  SearchStixCoreObjectsLinesPaginationQuery,
  SearchStixCoreObjectsLinesPaginationQuery$variables,
} from '@components/search/__generated__/SearchStixCoreObjectsLinesPaginationQuery.graphql';
import { Link, useHistory, useParams } from 'react-router-dom';
import Button from '@mui/material/Button';
import EEChip from '@components/common/entreprise_edition/EEChip';
import ListLines from '../../components/list_lines/ListLines';
import ToolBar from './data/ToolBar';
import SearchStixCoreObjectsLines, { searchStixCoreObjectsLinesQuery } from './search/SearchStixCoreObjectsLines';
import ExportContextProvider from '../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import useAuth from '../../utils/hooks/useAuth';
import useEnterpriseEdition from '../../utils/hooks/useEnterpriseEdition';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup, getDefaultFilterObjFromFilterDefinitions, useFilterDefinition } from '../../utils/filters/filtersUtils';
import { decodeSearchKeyword, handleSearchByKeyword } from '../../utils/SearchUtils';
import { useFormatter } from '../../components/i18n';

const LOCAL_STORAGE_KEY = 'search';

const Search = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isEnterpriseEdition = useEnterpriseEdition();
  const history = useHistory();
  const { t_i18n } = useFormatter();
  const { keyword } = useParams() as { keyword: string };
  const searchTerm = decodeSearchKeyword(keyword);

  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<SearchStixCoreObjectsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      sortBy: '_score',
      orderAsc: false,
      openExports: false,
      filters: {
        ...emptyFilterGroup,
        filters: getDefaultFilterObjFromFilterDefinitions([useFilterDefinition('entity_type', ['Stix-Core-Object'])]),
      },
    },
  );
  const {
    numberOfElements,
    filters,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle<SearchStixCoreObjectLine_node$data>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as SearchStixCoreObjectsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<SearchStixCoreObjectsLinesPaginationQuery>(
    searchStixCoreObjectsLinesQuery,
    { ...queryPaginationOptions, search: searchTerm },
  );

  const handleSearch = (searchKeyword: string) => {
    handleSearchByKeyword(searchKeyword, 'knowledge', history);
  };

  const resultsCount = numberOfElements?.original ?? 0;

  const renderLines = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      value: {
        label: 'Value',
        width: '22%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creator',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '16%',
        isSortable: false,
      },
      created_at: {
        label: 'Platform creation date',
        width: '10%',
        isSortable: true,
      },
      analyses: {
        label: 'Analyses',
        width: '8%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        width: '10%',
        isSortable: isRuntimeSort,
      },
    };

    return (
      <>
        <ListLines
          helpers={storageHelpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
          handleChangeView={storageHelpers.handleChangeView}
          handleToggleSelectAll={handleToggleSelectAll}
          handleToggleExports={storageHelpers.handleToggleExports}
          openExports={openExports}
          exportContext={{ entity_type: 'Stix-Core-Object' }}
          selectAll={selectAll}
          disableCards={true}
          filters={filters}
          keyword={searchTerm}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
        >
          {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <SearchStixCoreObjectLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
                      }
          >
            <SearchStixCoreObjectsLines
              queryRef={queryRef}
              paginationOptions={queryPaginationOptions}
              dataColumns={dataColumns}
              onLabelClick={storageHelpers.handleAddFilter}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              onToggleEntity={onToggleEntity}
              selectAll={selectAll}
              setNumberOfElements={storageHelpers.handleSetNumberOfElements}
            />
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              selectAll={selectAll}
              filters={contextFilters}
              search={searchTerm}
              handleClearSelectedElements={handleClearSelectedElements}
            />
          </React.Suspense>
          )}
        </ListLines>
      </>
    );
  };
  return (
    <ExportContextProvider>
      <>
        {renderLines()}
        {resultsCount <= 5 && searchTerm && (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
          <Button
            size="small"
            variant="outlined"
            component={Link}
            color={isEnterpriseEdition ? 'primary' : 'ee'}
            to={`/dashboard/search/files/${searchTerm}`}
          >
            <div>{t_i18n('Extend this search to indexed files')}<EEChip /></div>
          </Button>
        </div>
        )}
      </>
    </ExportContextProvider>
  );
};

export default Search;
