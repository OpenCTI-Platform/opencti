import { graphql } from 'react-relay';
import React, { useState } from 'react';
import ImportMenu from '@components/data/ImportMenu';
import { ImportWorkbenchesContentQuery, ImportWorkbenchesContentQuery$variables } from '@components/data/import/__generated__/ImportWorkbenchesContentQuery.graphql';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined, GetAppOutlined } from '@mui/icons-material';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { ImportWorkbenchesContentFileLine_file$data } from '@components/data/import/__generated__/ImportWorkbenchesContentFileLine_file.graphql';
import { ImportWorkbenchesContentLines_data$data } from '@components/data/import/__generated__/ImportWorkbenchesContentLines_data.graphql';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH } from '../../../../relay/environment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { deleteNode } from '../../../../utils/store';

export const WorkbenchFileLineDeleteMutation = graphql`
  mutation ImportWorkbenchesContentFileLineDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

export const workbenchLineFragment = graphql`
  fragment ImportWorkbenchesContentFileLine_file on File {
    id
    entity_type
    name
    uploadStatus
    lastModified
    lastModifiedSinceMin
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
    }
  }
`;

const importWorkbenchLinesFragment = graphql`
  fragment ImportWorkbenchesContentLines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 500 }
    cursor: { type: "ID" }
    orderBy: { type: "FileOrdering" }
    orderMode: { type: "OrderingMode" }
    search: { type: "String" }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ImportWorkbenchesRefetchQuery") {
    pendingFiles(
      first: $count,
      after: $cursor,
      orderBy: $orderBy,
      orderMode: $orderMode,
      search: $search,
      filters: $filters,
    )
    @connection(key: "Pagination_global_pendingFiles") {
      edges {
        node {
          ...ImportWorkbenchesContentFileLine_file
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

export const importWorkbenchesContentQuery = graphql`
  query ImportWorkbenchesContentQuery(
    $count: Int,
    $cursor: ID,
    $orderBy: FileOrdering,
    $orderMode: OrderingMode,
    $search: String,
    $filters: FilterGroup,
  ) {
    ...ImportWorkbenchesContentLines_data
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

const LOCAL_STORAGE_KEY = 'importWorkbenches';

const ImportWorkbenchesContent = () => {
  const { t_i18n } = useFormatter();
  const [displayDelete, setDisplayDelete] = useState<string>('');

  const initialFilters = {
    ...emptyFilterGroup,
    filters: [{
      key: 'entity_type',
      values: ['InternalFile'],
      operator: 'eq',
      mode: 'or',
    }, {
      key: 'entity_id',
      values: [],
      operator: 'nil',
    }, {
      key: 'file_id',
      values: ['import/pending'],
      operator: 'starts_with',
    }],
  };
  const initialValues = {
    filters: initialFilters,
    orderAsc: false,
  };
  const { helpers, paginationOptions } = usePaginationLocalStorage<ImportWorkbenchesContentQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: initialFilters,
  } as unknown as ImportWorkbenchesContentQuery$variables;

  const queryRef = useQueryLoading<ImportWorkbenchesContentQuery>(importWorkbenchesContentQuery, queryPaginationOptions);

  const preloadedPaginationProps = {
    linesQuery: importWorkbenchesContentQuery,
    linesFragment: importWorkbenchLinesFragment,
    queryRef,
    nodePath: ['pendingFiles', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ImportWorkbenchesContentQuery>;

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
        deleteNode(store, 'Pagination_global_pendingFiles', queryPaginationOptions, id);
      },
      onCompleted: () => setDisplayDelete(''),
      onError: () => setDisplayDelete(''),
    });
  };

  return (
    <div style={{ height: '100%', paddingRight: 200 }} className="break">
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Data') }, { label: t_i18n('Analyst Workbenches'), current: true }]} />
      <ImportMenu />
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={!!displayDelete}
        TransitionComponent={Transition}
        onClose={() => setDisplayDelete('')}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this workbench?')}
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
          dataColumns={{
            value: { percentWidth: 50 },
            createdBy: {
              percentWidth: 15,
              render: (({ metaData: { creator } }) => creator?.name ?? '-'),
            },
            objectLabel: {
              percentWidth: 15,
              render: ({ metaData: { labels } }) => {
                return (
                  <StixCoreObjectLabels
                    variant="inList"
                    labels={labels}
                  />
                );
              },
            },
            lastModified: {
              id: 'lastModified',
              label: 'Modification date',
              isSortable: true,
              percentWidth: 19,
              render: ({ lastModified }, { fd }) => fd(lastModified),
            },
          }}
          resolvePath={(data: ImportWorkbenchesContentLines_data$data) => data.pendingFiles?.edges?.map(({ node }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          entityTypes={['InternalFile']}
          searchContextFinal={{ entityTypes: ['InternalFile'] }}
          toolbarFilters={initialFilters}
          lineFragment={workbenchLineFragment}
          initialValues={initialValues}
          hideFilters
          preloadedPaginationProps={preloadedPaginationProps}
          taskScope='IMPORT'
          actions={(file: ImportWorkbenchesContentFileLine_file$data) => {
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
                <Tooltip title={t_i18n('Delete this workbench')}>
                  <IconButton
                    disabled={isProgress}
                    color={'primary'}
                    onClick={() => setDisplayDelete(id)}
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

export default ImportWorkbenchesContent;
