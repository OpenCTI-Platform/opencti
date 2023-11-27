import React from 'react';
import SearchIndexedFilesLines, { searchIndexedFilesLinesQuery } from '@components/search/SearchIndexedFilesLines';
import {
  SearchIndexedFilesLinesPaginationQuery,
  SearchIndexedFilesLinesPaginationQuery$variables,
} from '@components/search/__generated__/SearchIndexedFilesLinesPaginationQuery.graphql';
import { SearchIndexedFileLine_node$data } from '@components/search/__generated__/SearchIndexedFileLine_node.graphql';
import { useHistory, useParams } from 'react-router-dom';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { useFormatter } from '../../../components/i18n';
import ItemEntityType from '../../../components/ItemEntityType';
import ItemMarkings from '../../../components/ItemMarkings';
import useAuth from '../../../utils/hooks/useAuth';
import { decodeSearchKeyword, handleSearchByKeyword } from '../../../utils/SearchUtils';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

const LOCAL_STORAGE_KEY = 'view-files';
const SearchIndexedFilesComponent = () => {
  const { fd } = useFormatter();
  const history = useHistory();
  const {
    platformModuleHelpers: { isFileIndexManagerEnable },
  } = useAuth();
  const { keyword } = useParams() as { keyword: string };
  const searchTerm = decodeSearchKeyword(keyword);
  const {
    viewStorage,
    helpers: storageHelpers,
    paginationOptions,
  } = usePaginationLocalStorage<SearchIndexedFilesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      sortBy: '_score',
      orderAsc: true,
    },
    undefined,
    true,
  );

  const {
    numberOfElements,
    sortBy,
    orderAsc,
  } = viewStorage;

  const queryRef = useQueryLoading<SearchIndexedFilesLinesPaginationQuery>(
    searchIndexedFilesLinesQuery,
    { ...paginationOptions, search: searchTerm },
  );

  const handleSearch = (searchKeyword: string) => {
    handleSearchByKeyword(searchKeyword, 'files', history);
  };

  const fileSearchEnabled = isFileIndexManagerEnable();

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'File name',
        width: '25%',
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => node.name,
      },
      uploaded_at: {
        label: 'Upload date',
        width: '10%',
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => fd(node.uploaded_at),
      },
      occurrences: {
        label: 'Occurrences',
        width: '10%',
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => {
          return (node.searchOccurrences && node.searchOccurrences > 99) ? '99+' : node.searchOccurrences;
        },
      },
      entity_type: {
        label: 'Attached entity type',
        width: '15%',
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => (
          <>
            {node.entity && (
              <ItemEntityType entityType={node.entity.entity_type} />
            )}
          </>
        ),
      },
      entity_name: {
        label: 'Attached entity name',
        width: '25%',
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => (
          <>
            {node.entity && (
              <span>{node.entity?.representative.main}</span>
            )}
          </>
        ),
      },
      objectMarking: {
        label: 'Marking',
        width: '10%',
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => (
          <>
            {node.entity && (
              <ItemMarkings
                variant="inList"
                markingDefinitionsEdges={node.entity.objectMarking?.edges ?? []}
                limit={1}
              />
            )}
          </>
        ),
      },
    };

    return (
      <>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          keyword={searchTerm}
          disableCards={true}
          secondaryAction={true}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          availableFilterKeys={[]}
        >
          {queryRef && (
            <React.Suspense fallback={<Loader/>}>
              <SearchIndexedFilesLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                onLabelClick={storageHelpers.handleAddFilter}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
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
        {fileSearchEnabled && renderLines()}
      </div>
    </ExportContextProvider>
  );
};

const SearchIndexedFiles = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  if (!isEnterpriseEdition) {
    return (
      <EnterpriseEdition feature={'File indexing'} />
    );
  }
  return (
    <SearchIndexedFilesComponent />
  );
};

export default SearchIndexedFiles;
