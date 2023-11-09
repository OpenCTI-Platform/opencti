import React, { useState } from 'react';
import { KeyboardDoubleArrowDownOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { SearchStixCoreObjectLineDummy } from '@components/search/SearchStixCoreObjectLine';
import {
  SearchStixCoreObjectLine_node$data,
} from '@components/search/__generated__/SearchStixCoreObjectLine_node.graphql';
import {
  SearchStixCoreObjectsLinesPaginationQuery,
  SearchStixCoreObjectsLinesPaginationQuery$variables,
} from '@components/search/__generated__/SearchStixCoreObjectsLinesPaginationQuery.graphql';
import { useParams } from 'react-router-dom';
import Button from '@mui/material/Button';
import SearchIndexedFiles from '@components/search/SearchIndexedFiles';
import TopBar from './nav/TopBar';
import ListLines from '../../components/list_lines/ListLines';
import ToolBar from './data/ToolBar';
import SearchStixCoreObjectsLines, { searchStixCoreObjectsLinesQuery } from './search/SearchStixCoreObjectsLines';
import ExportContextProvider from '../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import { Filters } from '../../components/list_lines';
import useEntityToggle from '../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import useAuth from '../../utils/hooks/useAuth';
import { useFormatter } from '../../components/i18n';

const LOCAL_STORAGE_KEY = 'view-search';

const Search = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable, isFileIndexManagerEnable },
  } = useAuth();
  const { t } = useFormatter();
  const { keyword } = useParams() as { keyword: string };
  let searchTerm = '';
  try {
    searchTerm = decodeURIComponent(keyword || '');
  } catch (e) {
    // Do nothing
  }
  const fileSearchEnabled = isFileIndexManagerEnable();
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<SearchStixCoreObjectsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      sortBy: '_score',
      orderAsc: false,
      openExports: false,
      filters: {} as Filters,
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

  const queryRef = useQueryLoading<SearchStixCoreObjectsLinesPaginationQuery>(
    searchStixCoreObjectsLinesQuery,
    { ...paginationOptions, search: searchTerm },
  );
  const [searchOpen, setSearchOpen] = useState(false);
  const handleSearchIndexFiles = () => {
    setSearchOpen(true);
  };

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
        label: 'Creation date',
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
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={dataColumns}
              handleSort={storageHelpers.handleSort}
              handleAddFilter={storageHelpers.handleAddFilter}
              handleRemoveFilter={storageHelpers.handleRemoveFilter}
              handleChangeView={storageHelpers.handleChangeView}
              handleToggleSelectAll={handleToggleSelectAll}
              handleToggleExports={storageHelpers.handleToggleExports}
              openExports={openExports}
              exportEntityType="Stix-Core-Object"
              selectAll={selectAll}
              disableCards={true}
              filters={filters}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              iconExtension={true}
              availableFilterKeys={[
                'entity_type',
                'labelledBy',
                'markedBy',
                'createdBy',
                'source_reliability',
                'confidence',
                'x_opencti_organization_type',
                'creator',
                'created_start_date',
                'created_end_date',
                'created_at_start_date',
                'created_at_end_date',
              ]}
            >
              {queryRef && (
                  <React.Suspense
                      fallback={
                        <>
                          {Array(20)
                            .fill(0)
                            .map((idx) => (
                                  <SearchStixCoreObjectLineDummy key={idx} dataColumns={dataColumns} />
                            ))}
                        </>
                      }
                  >
                  <SearchStixCoreObjectsLines
                      queryRef={queryRef}
                      paginationOptions={paginationOptions}
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
                  filters={filters}
                  search={paginationOptions.search}
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
        <div>
          <TopBar keyword={searchTerm} />
          <Typography
            variant="h1"
            gutterBottom={true}
            style={{ margin: '-5px 20px 0 0', float: 'left' }}
          >
            {t('Search for an entity')}
          </Typography>
          {renderLines()}
          {fileSearchEnabled && searchTerm && (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
              <Button
                size="small"
                onClick={handleSearchIndexFiles}
              >
                <KeyboardDoubleArrowDownOutlined /> {t('Extend this search to indexed files')} <KeyboardDoubleArrowDownOutlined />
              </Button>
            </div>
          )}
          { searchOpen ? (<SearchIndexedFiles search={searchTerm}/>) : ('')}
        </div>
      </ExportContextProvider>
  );
};

export default Search;
