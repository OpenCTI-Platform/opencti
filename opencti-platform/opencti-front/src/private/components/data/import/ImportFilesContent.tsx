import { graphql } from 'react-relay';
import React, { useState } from 'react';
import ImportMenu from '@components/data/ImportMenu';
import { ImportFilesContentQuery, ImportFilesContentQuery$variables } from '@components/data/import/__generated__/ImportFilesContentQuery.graphql';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { ImportFilesContentLines_data$data } from '@components/data/import/__generated__/ImportFilesContentLines_data.graphql';
import { ImportFilesContentFileLine_file$data } from '@components/data/import/__generated__/ImportFilesContentFileLine_file.graphql';
import ImportActionsPopover from '@components/common/files/ImportActionsPopover';
import ImportFilesDialog from '@components/common/files/import_files/ImportFilesDialog';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { deleteNode } from '../../../../utils/store';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useHelper from '../../../../utils/hooks/useHelper';
import { getFileUri } from '../../../../utils/utils';
import ImportButton from '../../../../components/ImportButton';

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
    works {
      id
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
  const { isFeatureEnable } = useHelper();
  const isNewImportScreensEnabled = isFeatureEnable('NEW_IMPORT_SCREENS');
  const [displayDelete, setDisplayDelete] = useState<string>('');
  const [openImportFilesDialog, setOpenImportFilesDialog] = useState<boolean>(false);

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'lastModified',
    orderAsc: false,
  };

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<ImportFilesContentQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
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

  const [deleteFile] = useApiMutation(WorkbenchFileLineDeleteMutation);
  const handleRemoveFile = (id: string) => {
    deleteFile({
      variables: { fileName: id },
      optimisticUpdater: (store) => {
        const fileStore = store.get(id);
        fileStore?.setValue(0, 'lastModifiedSinceMin');
        fileStore?.setValue('progress', 'uploadStatus');
      },
      updater: (store) => {
        const fileStore = store.get(id);
        fileStore?.setValue(0, 'lastModifiedSinceMin');
        fileStore?.setValue('progress', 'uploadStatus');
        deleteNode(store, 'Pagination_global_importFiles', queryPaginationOptions, id);
      },
      onCompleted: () => setDisplayDelete(''),
      onError: () => setDisplayDelete(''),
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

  const dataColumns = {
    name: { percentWidth: 50 },
    createdBy: {
      percentWidth: 15,
      render: (({ metaData }: ImportFilesContentFileLine_file$data) => metaData?.creator?.name ?? '-'),
    },
    objectMarking: {
      percentWidth: 15,
    },
    lastModified: {
      id: 'lastModified',
      label: 'Modification date',
      isSortable: true,
      percentWidth: 19,
      render: ({ lastModified }: ImportFilesContentFileLine_file$data, { fd }: {
        fd: (date: Date) => string
      }) => fd(lastModified),
    },
  };

  // const buttonUploadFile = <

  return (
    <div style={{ height: '100%', paddingRight: isNewImportScreensEnabled ? 0 : 200 }} className="break">
      {isNewImportScreensEnabled ? (
        <>
          <Breadcrumbs
            elements={[{ label: t_i18n('Data') }, { label: t_i18n('Import'), current: true }]}
          />
          <ImportMenu/>
        </>
      ) : (
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Uploaded Files'), current: true }]}/>
      )}
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={!!displayDelete}
        slots={{ transition: Transition }}
        onClose={() => setDisplayDelete('')}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this file?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayDelete('')}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => handleRemoveFile(displayDelete)}
            color="secondary"
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ImportFilesContentLines_data$data) => data.importFiles?.edges?.map(({ node }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={toolbarFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={workbenchLineFragment}
          entityTypes={['InternalFile']}
          searchContextFinal={{ entityTypes: ['InternalFile'] }}
          taskScope={'IMPORT'}
          redirectionModeEnabled
          onLineClick={(file: ImportFilesContentFileLine_file$data) => {
            const { id, metaData, uploadStatus } = file;
            const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
            if (!isProgress && !(metaData?.errors && metaData?.errors.length > 0)) {
              window.location.pathname = getFileUri(id);
            }
          }}
          createButton={<ImportButton onClick={() => setOpenImportFilesDialog(true)}/>}
          actions={(file: ImportFilesContentFileLine_file$data) => (
            <ImportActionsPopover
              file={file}
              paginationOptions={queryPaginationOptions}
              paginationKey={'Pagination_global_importFiles'}
            />
          )}
        />
      )}
      {openImportFilesDialog && (
        <ImportFilesDialog open={openImportFilesDialog} handleClose={() => setOpenImportFilesDialog(false)}/>
      )}
    </div>
  );
};

export default ImportFilesContent;
