import React, { FunctionComponent } from 'react';
import SearchIndexedFilesLines, { searchIndexedFilesLinesQuery } from '@components/search/SearchIndexedFilesLines';
import {
  SearchIndexedFilesLinesPaginationQuery,
  SearchIndexedFilesLinesPaginationQuery$variables,
} from '@components/search/__generated__/SearchIndexedFilesLinesPaginationQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import ExportContextProvider from '../../../utils/ExportContextProvider';

interface SearchIndexedFilesProps {
  search: string;
}
const LOCAL_STORAGE_KEY = 'view-files';
const SearchIndexedFiles : FunctionComponent<SearchIndexedFilesProps> = ({ search }) => {
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
    { ...paginationOptions, search },
  );

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Filename',
        width: '25%',
        isSortable: false,
      },
      uploaded_at: {
        label: 'Upload date',
        width: '10%',
        isSortable: false,
      },
      occurrences: {
        label: 'Occurrences',
        width: '10%',
        isSortable: false,
      },
      entity_type: {
        label: 'Attached entity type',
        width: '15%',
        isSortable: false,
      },
      entity_name: {
        label: 'Attached entity name',
        width: '25%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Attached entity marking',
        width: '10%',
        isSortable: false,
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
      {renderLines()}
    </ExportContextProvider>
  );
};

export default SearchIndexedFiles;
