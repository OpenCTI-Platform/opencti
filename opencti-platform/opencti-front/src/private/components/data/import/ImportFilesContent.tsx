import { graphql } from 'react-relay';
import React, { useState } from 'react';
import ImportMenu from '@components/data/ImportMenu';
import { ImportFilesContentQuery, ImportFilesContentQuery$variables } from '@components/data/import/__generated__/ImportFilesContentQuery.graphql';
import { ImportFilesContentLines_data$data } from '@components/data/import/__generated__/ImportFilesContentLines_data.graphql';
import { ImportFilesContentFileLine_file$data } from '@components/data/import/__generated__/ImportFilesContentFileLine_file.graphql';
import ImportActionsPopover from '@components/common/files/ImportActionsPopover';
import ImportFilesDialog from '@components/common/files/import_files/ImportFilesDialog';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { getFileUri } from '../../../../utils/utils';
import UploadImport from '../../../../components/UploadImport';

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

interface ImportFilesContentProps {
  inDraftOverview?: boolean;
}

const ImportFilesContent = ({ inDraftOverview }: ImportFilesContentProps) => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Upload Files | Import | Data'));
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

  const contextFilters = {
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
        key: 'internal_id',
        values: ['import/global'],
        operator: 'starts_with',
      },
    ],
    filterGroups: finalFilters && isFilterGroupNotEmpty(finalFilters) ? [finalFilters] : [],
  };

  const dataColumns = {
    name: { percentWidth: 50 },
    createdBy: {
      label: 'Creator',
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
      percentWidth: 20,
      render: ({ lastModified }: ImportFilesContentFileLine_file$data, { fd }: {
        fd: (date: Date) => string
      }) => fd(lastModified),
    },
  };

  return (
    <div style={{ height: '100%' }} className="break" data-testid="file-page">
      {!inDraftOverview && (
        <>
          <Breadcrumbs
            elements={[{ label: t_i18n('Data') }, { label: t_i18n('Import'), current: true }]}
          />
          <ImportMenu/>
        </>
      )}
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ImportFilesContentLines_data$data) => data.importFiles?.edges?.map(({ node }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={workbenchLineFragment}
          entityTypes={['InternalFile']}
          searchContextFinal={{ entityTypes: ['InternalFile'] }}
          taskScope={'IMPORT'}
          onLineClick={(file: ImportFilesContentFileLine_file$data) => {
            const { id, metaData, uploadStatus } = file;
            const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
            if (!isProgress && !(metaData?.errors && metaData?.errors.length > 0)) {
              window.open(getFileUri(id), '_blank', 'noreferrer');
            }
          }}
          createButton={<UploadImport variant="contained"/>}
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
