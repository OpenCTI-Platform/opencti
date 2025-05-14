import { graphql } from 'react-relay';
import React, { useState } from 'react';
import ImportMenu from '@components/data/ImportMenu';
import { ImportFilesContentQuery, ImportFilesContentQuery$variables } from '@components/data/import/__generated__/ImportFilesContentQuery.graphql';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined, GetAppOutlined } from '@mui/icons-material';
import { ImportFilesContentLines_data$data } from '@components/data/import/__generated__/ImportFilesContentLines_data.graphql';
import { ImportFilesContentFileLine_file$data } from '@components/data/import/__generated__/ImportFilesContentFileLine_file.graphql';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH } from '../../../../relay/environment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { deleteNode } from '../../../../utils/store';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import stopEvent from '../../../../utils/domEvent';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';

export const WorkbenchFileLineDeleteMutation = graphql`
  mutation ImportFilesContentFileLineDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

export const workbenchLineFragment = graphql`
  fragment ImportFilesContentFileLine_file on File {
    id
    entity_type
    name
    uploadStatus
    lastModified
    lastModifiedSinceMin
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    metaData {
      mimetype
      list_filters
      labels
      messages {
        timestamp
        message
      }
      errors {
        timestamp
        message
      }
      creator {
        name
      }
      entity_id
    }
  }
`;

const importWorkbenchLinesFragment = graphql`
  fragment ImportFilesContentLines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 500 }
    cursor: { type: "ID" }
    orderBy: { type: "FileOrdering" }
    orderMode: { type: "OrderingMode" }
    search: { type: "String" }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ImportFilesRefetchQuery") {
    importFiles(
      first: $count,
      after: $cursor,
      orderBy: $orderBy,
      orderMode: $orderMode,
      search: $search,
      filters: $filters,
    )
    @connection(key: "Pagination_global_importFiles") {
      edges {
        node {
          id
          ...ImportFilesContentFileLine_file
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

export const importFilesContentQuery = graphql`
  query ImportFilesContentQuery(
    $count: Int,
    $cursor: ID,
    $orderBy: FileOrdering,
    $orderMode: OrderingMode,
    $search: String,
    $filters: FilterGroup,
  ) {
    ...ImportFilesContentLines_data
    @arguments(
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      search: $search
      filters: $filters
    )
  }
`;

const LOCAL_STORAGE_KEY = 'importFiles';

const ImportFilesContent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Upload Files | Import | Data'));
  const [fileId, setFileId] = useState<string>('');

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'lastModified',
    orderAsc: false,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ImportFilesContentQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const { filters } = viewStorage;
  const finalFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['InternalFile']);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: finalFilters,
  } as unknown as ImportFilesContentQuery$variables;

  const queryRef = useQueryLoading<ImportFilesContentQuery>(importFilesContentQuery, queryPaginationOptions);

  const preloadedPaginationProps = {
    linesQuery: importFilesContentQuery,
    linesFragment: importWorkbenchLinesFragment,
    queryRef,
    nodePath: ['importFiles', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ImportFilesContentQuery>;

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const handleRemove = (e: React.MouseEvent<HTMLButtonElement, MouseEvent>, id: string) => {
    stopEvent(e);
    setFileId(id);
    handleOpenDelete();
  };

  const [deleteFile] = useApiMutation(WorkbenchFileLineDeleteMutation);
  const handleRemoveFile = () => {
    deleteFile({
      variables: { fileName: fileId },
      optimisticUpdater: (store) => {
        const fileStore = store.get(fileId);
        fileStore?.setValue(0, 'lastModifiedSinceMin');
        fileStore?.setValue('progress', 'uploadStatus');
      },
      updater: (store) => {
        const fileStore = store.get(fileId);
        fileStore?.setValue(0, 'lastModifiedSinceMin');
        fileStore?.setValue('progress', 'uploadStatus');
        deleteNode(store, 'Pagination_global_importFiles', queryPaginationOptions, fileId);
      },
      onCompleted: () => {
        setFileId('');
        handleCloseDelete();
      },
      onError: () => {
        setFileId('');
        handleCloseDelete();
      },
    });
  };

  const toolbarFilters = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: ['InternalFile'],
        operator: 'eq',
        mode: 'or',
      },
      {
        key: 'entity_id',
        values: [],
        operator: 'nil',
      },
      {
        key: 'file_id',
        values: ['import/global'],
        operator: 'starts_with',
      },
    ],
    filterGroups: finalFilters ? [finalFilters] : [],
  };

  return (
    <div style={{ height: '100%', paddingRight: 200 }} className="break">
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Uploaded Files'), current: true }]} />
      <ImportMenu />
      <DeleteDialog
        deletion={deletion}
        submitDelete={handleRemoveFile}
        message={t_i18n('Do you want to delete this file?')}
      />
      {queryRef && (
        <DataTable
          dataColumns={{
            name: { percentWidth: 50 },
            createdBy: {
              percentWidth: 15,
              render: (({ metaData: { creator } }) => creator?.name ?? '-'),
            },
            objectMarking: {
              percentWidth: 15,
            },
            lastModified: {
              id: 'lastModified',
              label: 'Modification date',
              isSortable: true,
              percentWidth: 19,
              render: ({ lastModified }, { fd }) => fd(lastModified),
            },
          }}
          resolvePath={(data: ImportFilesContentLines_data$data) => data.importFiles?.edges?.map(({ node }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          entityTypes={['InternalFile']}
          searchContextFinal={{ entityTypes: ['InternalFile'] }}
          toolbarFilters={toolbarFilters}
          lineFragment={workbenchLineFragment}
          initialValues={initialValues}
          preloadedPaginationProps={preloadedPaginationProps}
          taskScope={'IMPORT'}
          actions={(file: ImportFilesContentFileLine_file$data) => {
            const { id, metaData, uploadStatus } = file;
            const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
            return (
              <div style={{ marginLeft: -10 }}>
                {!(metaData?.errors && metaData?.errors.length > 0) && (
                  <Tooltip title={t_i18n('Download this file')}>
                    <IconButton
                      disabled={isProgress}
                      href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(id)}`}
                      aria-haspopup="true"
                      color={'primary'}
                      size="small"
                    >
                      <GetAppOutlined fontSize="small" />
                    </IconButton>
                  </Tooltip>
                )}
                <Tooltip title={t_i18n('Delete this file')}>
                  <IconButton
                    disabled={isProgress}
                    color={'primary'}
                    onClick={(e) => handleRemove(e, id)}
                    size="small"
                  >
                    <DeleteOutlined fontSize="small" />
                  </IconButton>
                </Tooltip>
              </div>
            );
          }}
        />
      )}
    </div>
  );
};

export default ImportFilesContent;
