import { graphql } from 'react-relay';
import React from 'react';
import { ImportWorkbenchesContentQuery, ImportWorkbenchesContentQuery$variables } from '@components/data/import/__generated__/ImportWorkbenchesContentQuery.graphql';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import { ImportWorkbenchesContentFileLine_file$data } from '@components/data/import/__generated__/ImportWorkbenchesContentFileLine_file.graphql';
import ImportMenu from '@components/data/ImportMenu';
import WorkbenchCreation from '@components/common/files/workbench/WorkbenchCreation';
import ImportActionsPopover from '@components/common/files/ImportActionsPopover';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { toB64 } from '../../../../utils/String';
import { ImportWorkbenchesContentLines_data$data } from './__generated__/ImportWorkbenchesContentLines_data.graphql';

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
      labels_text
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
    works {
      id
    }
    ...FileWork_file
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
                    id
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

export const LOCAL_STORAGE_KEY = 'importWorkbenches';

const ImportWorkbenchesContent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Analyst Workbench | Import | Data'));

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
  } = usePaginationLocalStorage<ImportWorkbenchesContentQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const { filters } = viewStorage;
  const finalFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['InternalFile']);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: finalFilters,
  } as unknown as ImportWorkbenchesContentQuery$variables;

  const queryRef = useQueryLoading<ImportWorkbenchesContentQuery>(importWorkbenchesContentQuery, queryPaginationOptions);

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
        values: ['import/pending'],
        operator: 'starts_with',
      },
    ],
    filterGroups: finalFilters && isFilterGroupNotEmpty(finalFilters) ? [finalFilters] : [],
  };

  const preloadedPaginationProps = {
    linesQuery: importWorkbenchesContentQuery,
    linesFragment: importWorkbenchLinesFragment,
    queryRef,
    nodePath: ['pendingFiles', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ImportWorkbenchesContentQuery>;

  const dataColumns = {
    name: { percentWidth: 50 },
    createdBy: {
      label: 'Creator',
      percentWidth: 10,
      render: (({ metaData }: ImportWorkbenchesContentFileLine_file$data) => metaData?.creator?.name ?? '-'),
    },
    objectLabel: {
      percentWidth: 10,
      render: ({ metaData }: ImportWorkbenchesContentFileLine_file$data) => {
        const labels = metaData?.labels?.filter((l) => !!l)?.map((l) => ({ value: l, id: l as string, color: undefined }));
        return (
          <StixCoreObjectLabels
            variant="inList"
            labels={labels}
          />
        );
      },
    },
    objectMarking: {
      percentWidth: 10,
    },
    lastModified: {
      id: 'lastModified',
      label: 'Modification date',
      isSortable: true,
      percentWidth: 20,
      render: ({ lastModified }: ImportWorkbenchesContentFileLine_file$data, { fd }: {
        fd: (date: Date) => string
      }) => fd(lastModified),
    },
  };

  return (
    <div style={{ height: '100%' }} className="break" data-testid="workbench-page">
      <Breadcrumbs
        elements={[{ label: t_i18n('Data') }, { label: t_i18n('Import'), current: true }]}
      />
      <ImportMenu/>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ImportWorkbenchesContentLines_data$data) => data.pendingFiles?.edges?.map(({ node }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={workbenchLineFragment}
          entityTypes={['InternalFile']}
          searchContextFinal={{ entityTypes: ['InternalFile'] }}
          taskScope={'IMPORT'}
          getComputeLink={({ id }: ImportWorkbenchesContentFileLine_file$data) => (
            `/dashboard/data/import/workbench/${toB64(id)}`
          )}
          createButton={<WorkbenchCreation paginationOptions={queryPaginationOptions}/>}
          actions={(file: ImportWorkbenchesContentFileLine_file$data) => (
            <ImportActionsPopover
              file={file}
              paginationOptions={queryPaginationOptions}
              paginationKey={'Pagination_global_pendingFiles'}
            />
          )}
        />
      )}
    </div>
  );
};

export default ImportWorkbenchesContent;
