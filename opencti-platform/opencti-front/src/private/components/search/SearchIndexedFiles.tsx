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
import { SearchIndexedFileLine_node$data } from '@components/search/__generated__/SearchIndexedFileLine_node.graphql';
import { Link, useParams } from 'react-router-dom';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Button from '@common/button/Button';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { useFormatter } from '../../../components/i18n';
import ItemEntityType from '../../../components/ItemEntityType';
import ItemMarkings from '../../../components/ItemMarkings';
import useAuth from '../../../utils/hooks/useAuth';
import { decodeSearchKeyword } from '../../../utils/SearchUtils';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useManagerConfiguration from '../../../utils/hooks/useManagerConfiguration';
import Security from '../../../utils/Security';
import useGranted, { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD, SETTINGS_FILEINDEXING } from '../../../utils/hooks/useGranted';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { graphql } from 'react-relay';
import DataTable from '../../../components/dataGrid/DataTable';
import { SearchIndexedFilesPaginationQuery, SearchIndexedFilesPaginationQuery$variables } from './__generated__/SearchIndexedFilesPaginationQuery.graphql';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { SearchIndexedFiles_data$data } from '@components/search/__generated__/SearchIndexedFiles_data.graphql';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { OpenInNewOutlined } from '@mui/icons-material';
import { resolveLink } from '../../../utils/Entity';
import { getFileUri } from '../../../utils/utils';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';

const SearchIndexedFileLineFragment = graphql`
  fragment SearchIndexedFilesFile_node on IndexedFile {
    id
    name
    uploaded_at
    file_id
    searchOccurrences
    entity {
      ...on StixObject {
        id
        entity_type
        representative {
          main
        }
      }
      ...on StixCoreObject {
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
  }
`;

export const searchIndexedFilesLinesQuery = graphql`
  query SearchIndexedFilesPaginationQuery(
    $search: String
    $first: Int
    $cursor: ID
  ) {
    ...SearchIndexedFiles_data
    @arguments(
      search: $search
      first: $first
      cursor: $cursor
    )
  }
`;

export const searchIndexedFilesLinesFragment = graphql`
  fragment SearchIndexedFiles_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    first: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "SearchIndexedFilesLinesRefetchQuery") {
    indexedFiles(
      search: $search
      first: $first
      after: $cursor
    ) @connection(key: "Pagination_indexedFiles") {
      edges {
        node {
          id
          ...SearchIndexedFilesFile_node
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

const LOCAL_STORAGE_KEY = 'view-files';

const SearchIndexedFilesComponent = () => {
  const { fd, t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Files Search | Advanced Search'));
  const {
    platformModuleHelpers: { isFileIndexManagerEnable },
  } = useAuth();
  const isGrantedToFiles = useGranted([KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]);

  const managerConfiguration = useManagerConfiguration();
  const isFileIndexingRunning = managerConfiguration?.manager_running || false;
  const { keyword } = useParams() as { keyword: string };
  const searchTerm = decodeSearchKeyword(keyword);

  const initialValues = {
    sortBy: '_score',
    orderAsc: true,
  };
  const {
    helpers: storageHelpers,
    paginationOptions,
  } = usePaginationLocalStorage<SearchIndexedFilesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );

  const queryPaginationOptions = {
    ...paginationOptions,
    search: searchTerm,
  };

  const queryRef = useQueryLoading(
    searchIndexedFilesLinesQuery,
    queryPaginationOptions,
  );

  const fileSearchEnabled = isFileIndexManagerEnable();

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'File name',
        percentWidth: 30,
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => defaultRender(node.name),
      },
      uploaded_at: {
        label: 'Upload date',
        percentWidth: 10,
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => fd(node.uploaded_at),
      },
      occurrences: {
        label: 'Occurrences',
        percentWidth: 10,
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => {
          return (node.searchOccurrences && node.searchOccurrences > 99) ? '99+' : node.searchOccurrences;
        },
      },
      entity_type: {
        label: 'Attached entity type',
        percentWidth: 15,
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
        percentWidth: 25,
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => (
          <>
            {node.entity && (
              <>{defaultRender(node.entity?.representative.main)}</>
            )}
          </>
        ),
      },
      objectMarking: {
        percentWidth: 10,
        isSortable: false,
        render: (node: SearchIndexedFileLine_node$data) => (
          <>
            {node.entity && (
              <ItemMarkings
                markingDefinitions={node.entity.objectMarking ?? []}
                limit={1}
              />
            )}
          </>
        ),
      },
    };

    const preloadedPaginationOptions = {
      linesQuery: searchIndexedFilesLinesQuery,
      linesFragment: searchIndexedFilesLinesFragment,
      queryRef,
      nodePath: ['indexedFiles', 'pageInfo', 'globalCount'],
      setNumberOfElements: storageHelpers.handleSetNumberOfElements,
    } as UsePreloadedPaginationFragment<SearchIndexedFilesPaginationQuery>;

    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: SearchIndexedFiles_data$data) => data.indexedFiles?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            globalSearch={searchTerm}
            lineFragment={SearchIndexedFileLineFragment}
            preloadedPaginationProps={preloadedPaginationOptions}
            hideSearch
            disableLineSelection
            onLineClick={(file) => window.open(getFileUri(file.file_id), '_blank')}
            actions={(node) => {
              let entityLink = node.entity ? `${resolveLink(node.entity.entity_type)}/${node.entity.id}` : '';
              if (entityLink && isGrantedToFiles && node.entity?.entity_type !== 'External-Reference') {
                entityLink = entityLink.concat('/files');
              }
              if (node.entity && entityLink) {
                return (
                  <Tooltip title={t_i18n('Open the entity overview in a separated tab')}>
                    <IconButton
                      onClick={() => window.open(entityLink, '_blank')}
                    >
                      <OpenInNewOutlined fontSize="medium" />
                    </IconButton>
                  </Tooltip>
                );
              }
            }}
          />
        )}
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
