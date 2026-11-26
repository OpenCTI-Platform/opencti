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
import { SearchIndexedFilesFile_node$data } from './__generated__/SearchIndexedFilesFile_node.graphql';
import { Link, useNavigate, useParams } from 'react-router';
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
import useGranted, { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD } from '../../../utils/hooks/useGranted';
import useVisibleEntries from '../common/menus/useVisibleEntries';
import { fileIndexing } from '../settings/Settings.entries';
import useSwitchDraft from '../drafts/useSwitchDraft';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { graphql } from 'react-relay';
import DataTable from '../../../components/dataGrid/DataTable';
import { SearchIndexedFilesPaginationQuery, SearchIndexedFilesPaginationQuery$variables } from './__generated__/SearchIndexedFilesPaginationQuery.graphql';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { SearchIndexedFiles_data$data } from './__generated__/SearchIndexedFiles_data.graphql';
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
  const { ftd, t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Files Search | Advanced Search'));
  const {
    platformModuleHelpers: { isFileIndexManagerEnable },
  } = useAuth();
  const isGrantedToFiles = useGranted([KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]);

  const managerConfiguration = useManagerConfiguration();
  const isFileIndexingRunning = managerConfiguration?.manager_running || false;
  // Same rules as the File indexing page. The second entry ignores the draft rule: who could open it outside the draft.
  const fileIndexingOutsideDraft = { ...fileIndexing, availableInDraft: true };
  const visibleFileIndexing = useVisibleEntries([fileIndexing, fileIndexingOutsideDraft]);
  const navigate = useNavigate();
  const { exitDraft } = useSwitchDraft();
  const exitDraftToFileIndexing = () => exitDraft({
    onCompleted: () => {
      navigate(fileIndexing.path);
    },
  });
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
        render: (node: SearchIndexedFilesFile_node$data) => defaultRender(node.name),
      },
      uploaded_at: {
        label: 'Upload date',
        percentWidth: 10,
        isSortable: false,
        render: (node: SearchIndexedFilesFile_node$data) => defaultRender(ftd(node.uploaded_at)),
      },
      occurrences: {
        label: 'Occurrences',
        percentWidth: 10,
        isSortable: false,
        render: (node: SearchIndexedFilesFile_node$data) => {
          return (node.searchOccurrences && node.searchOccurrences > 99) ? '99+' : node.searchOccurrences;
        },
      },
      entity_type: {
        label: 'Attached entity type',
        percentWidth: 15,
        isSortable: false,
        render: (node: SearchIndexedFilesFile_node$data) => (
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
        render: (node: SearchIndexedFilesFile_node$data) => (
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
        render: (node: SearchIndexedFilesFile_node$data) => (
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
                      aria-label={t_i18n('Open the entity overview in a separated tab')}
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
            style={{ marginBottom: 30 }}
          >
            <AlertTitle style={{ marginBottom: 0 }}>
              {t_i18n('File indexing is not started.')}
              {visibleFileIndexing.includes(fileIndexing) && (
                <Button
                  component={Link}
                  size="small"
                  to={fileIndexing.path}
                  variant="secondary"
                  sx={{ marginLeft: 1 }}
                >
                  {t_i18n('Configure file indexing')}
                </Button>
              )}
              {/* In a draft, where the page is closed: offer to leave the draft to reach it. */}
              {!visibleFileIndexing.includes(fileIndexing) && visibleFileIndexing.includes(fileIndexingOutsideDraft) && (
                <Button
                  size="small"
                  variant="secondary"
                  sx={{ marginLeft: 1 }}
                  onClick={exitDraftToFileIndexing}
                >
                  {t_i18n('Exit draft and configure file indexing')}
                </Button>
              )}
              {!visibleFileIndexing.includes(fileIndexingOutsideDraft) && (
                <span>&nbsp;{t_i18n('Please contact your administrator.')}</span>
              )}
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
