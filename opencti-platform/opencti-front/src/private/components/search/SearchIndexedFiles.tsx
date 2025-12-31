/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import SearchIndexedFilesLines, { searchIndexedFilesLinesQuery } from '@components/search/SearchIndexedFilesLines';
import {
  SearchIndexedFilesLinesPaginationQuery,
  SearchIndexedFilesLinesPaginationQuery$variables,
} from '@components/search/__generated__/SearchIndexedFilesLinesPaginationQuery.graphql';
import { SearchIndexedFileLine_node$data } from '@components/search/__generated__/SearchIndexedFileLine_node.graphql';
import { Link, useParams } from 'react-router-dom';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Button from '@common/button/Button';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { useFormatter } from '../../../components/i18n';
import ItemEntityType from '../../../components/ItemEntityType';
import ItemMarkings from '../../../components/ItemMarkings';
import useAuth from '../../../utils/hooks/useAuth';
import { decodeSearchKeyword } from '../../../utils/SearchUtils';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useManagerConfiguration from '../../../utils/hooks/useManagerConfiguration';
import Security from '../../../utils/Security';
import { SETTINGS_FILEINDEXING } from '../../../utils/hooks/useGranted';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'view-files';
const SearchIndexedFilesComponent = () => {
  const { fd, t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Files Search | Advanced Search'));
  const {
    platformModuleHelpers: { isFileIndexManagerEnable },
  } = useAuth();
  const managerConfiguration = useManagerConfiguration();
  const isFileIndexingRunning = managerConfiguration?.manager_running || false;
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
                markingDefinitions={node.entity.objectMarking ?? []}
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
          helpers={storageHelpers}
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
        >
          {queryRef && (
            <React.Suspense fallback={<Loader />}>
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
        {!isFileIndexingRunning && (
          <Alert
            severity="warning"
            variant="outlined"
            style={{ position: 'relative', marginBottom: 30 }}
          >
            <AlertTitle style={{ marginBottom: 0 }}>
              {t_i18n('File indexing is not started.')}
              <Security needs={[SETTINGS_FILEINDEXING]} placeholder={<span>&nbsp;{t_i18n('Please contact your administrator.')}</span>}>
                <Button
                  component={Link}
                  size="small"
                  to="/dashboard/settings/file_indexing"
                  color="warning"
                  variant="secondary"
                  style={{ marginLeft: 20 }}
                >
                  {t_i18n('Configure file indexing')}
                </Button>
              </Security>
            </AlertTitle>
          </Alert>
        )}
        {fileSearchEnabled && renderLines()}
      </div>
    </ExportContextProvider>
  );
};

const SearchIndexedFiles = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  if (!isEnterpriseEdition) {
    return (
      <EnterpriseEdition feature="File indexing" />
    );
  }
  return (
    <SearchIndexedFilesComponent />
  );
};

export default SearchIndexedFiles;
