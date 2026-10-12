import { useState } from 'react';
import { graphql } from 'react-relay';
import { DialogActions, Typography } from '@mui/material';
import { DeleteOutlined } from '@mui/icons-material';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { deleteNode } from '../../../../utils/store';
import { MESSAGING$ } from '../../../../relay/environment';
import IocValidationRequestDetails from './IocValidationRequestDetails';
import { RequestStatusChip } from './DisseminationStatusChips';
import { TEST_KINDS } from './disseminationAssuranceUtils';
import type { IocValidationRequestsLine_node$data } from './__generated__/IocValidationRequestsLine_node.graphql';
import type { IocValidationRequestsLines_data$data } from './__generated__/IocValidationRequestsLines_data.graphql';
import type {
  IocValidationRequestsLinesPaginationQuery,
  IocValidationRequestsLinesPaginationQuery$variables,
} from './__generated__/IocValidationRequestsLinesPaginationQuery.graphql';
import type { IocValidationRequestsDeletionMutation } from './__generated__/IocValidationRequestsDeletionMutation.graphql';

const ENTITY_TYPE_IOC_VALIDATION_REQUEST = 'Ioc-Validation-Request';
const LOCAL_STORAGE_KEY = 'ioc-validation-requests';

const requestsLineFragment = graphql`
  fragment IocValidationRequestsLine_node on IocValidationRequest {
    id
    entity_type
    name
    status
    status_message
    test_kinds
    indicators_count
    created_at
    completed_at
    requested_by {
      id
      name
    }
    platforms {
      id
      name
    }
    results_summary {
      total
      detected
      prevented
      missed
      error
      skipped
    }
  }
`;

const requestsLinesQuery = graphql`
  query IocValidationRequestsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IocValidationRequestsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IocValidationRequestsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const requestsLinesFragment = graphql`
  fragment IocValidationRequestsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IocValidationRequestsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IocValidationRequestsLinesRefetchQuery") {
    iocValidationRequests(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_iocValidationRequests") {
      edges {
        node {
          id
          ...IocValidationRequestsLine_node
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

const requestDeletionMutation = graphql`
  mutation IocValidationRequestsDeletionMutation($id: ID!) {
    iocValidationRequestDelete(id: $id)
  }
`;

const RequestDeletion = ({ id, paginationOptions }: { id: string; paginationOptions: IocValidationRequestsLinesPaginationQuery$variables }) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [commit, deleting] = useApiMutation<IocValidationRequestsDeletionMutation>(requestDeletionMutation);
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <IconButton
            variant="default"
            priority="tertiary"
            size="md"
            aria-label={t_i18n('Delete')}
            onClick={(event: React.MouseEvent) => {
              event.preventDefault();
              event.stopPropagation();
              setOpen(true);
            }}
            icon={<DeleteOutlined fontSize="small" />}
          />
        </TooltipTrigger>
        <TooltipContent>{t_i18n('Delete')}</TooltipContent>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} title={t_i18n('Are you sure?')} size="small">
        <Typography>
          {t_i18n('Do you want to delete this validation request? The validation results already written on the deployments are kept.')}
        </Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setOpen(false)} disabled={deleting}>{t_i18n('Cancel')}</Button>
          <Button
            disabled={deleting}
            onClick={() => commit({
              variables: { id },
              // Payload errors reach the updater and onCompleted: only a returned id confirms the deletion.
              updater: (store, data) => {
                if (data?.iocValidationRequestDelete) deleteNode(store, 'Pagination_iocValidationRequests', paginationOptions, id);
              },
              onCompleted: (response, errors) => {
                if (errors && errors.length > 0) {
                  MESSAGING$.notifyError(errors[0].message);
                } else if (response.iocValidationRequestDelete) {
                  setOpen(false);
                  MESSAGING$.notifySuccess(t_i18n('Validation request deleted'));
                }
              },
            })}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const IocValidationRequests = () => {
  const { t_i18n, n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Dissemination assurance | Defense'));
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const [selected, setSelected] = useState<{ id: string; name: string } | null>(null);
  const initialValues = {
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<IocValidationRequestsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext(ENTITY_TYPE_IOC_VALIDATION_REQUEST, viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as IocValidationRequestsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<IocValidationRequestsLinesPaginationQuery>(requestsLinesQuery, queryPaginationOptions);
  const preloadedPaginationProps = {
    linesQuery: requestsLinesQuery,
    linesFragment: requestsLinesFragment,
    queryRef,
    nodePath: ['iocValidationRequests', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<IocValidationRequestsLinesPaginationQuery>;

  const testKindLabel = (kind: string) => {
    const definition = TEST_KINDS.find((d) => d.kind === kind);
    return definition ? t_i18n(definition.label) : kind;
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: t_i18n('Name'),
      percentWidth: 20,
      isSortable: true,
    },
    status: {
      id: 'status',
      label: t_i18n('Status'),
      percentWidth: 12,
      isSortable: true,
      render: ({ status }: IocValidationRequestsLine_node$data) => <RequestStatusChip status={status} />,
    },
    platforms: {
      id: 'platforms',
      label: t_i18n('Security platforms'),
      percentWidth: 13,
      isSortable: false,
      render: ({ platforms }: IocValidationRequestsLine_node$data) => defaultRender(platforms.map((p) => p.name)),
    },
    indicators_count: {
      id: 'indicators_count',
      label: t_i18n('Indicators'),
      percentWidth: 8,
      isSortable: false,
      render: ({ indicators_count }: IocValidationRequestsLine_node$data) => defaultRender(n(indicators_count)),
    },
    test_kinds: {
      id: 'test_kinds',
      label: t_i18n('Test kinds'),
      percentWidth: 12,
      isSortable: false,
      render: ({ test_kinds }: IocValidationRequestsLine_node$data) => defaultRender(test_kinds.map(testKindLabel)),
    },
    results: {
      id: 'results',
      label: t_i18n('Proven / missed'),
      percentWidth: 10,
      isSortable: false,
      render: ({ results_summary }: IocValidationRequestsLine_node$data) => defaultRender(
        `${n(results_summary.detected + results_summary.prevented)} / ${n(results_summary.missed)}`,
      ),
    },
    created_at: {
      id: 'created_at',
      label: t_i18n('Creation date'),
      percentWidth: 10,
      isSortable: true,
    },
    completed_at: {
      id: 'completed_at',
      label: t_i18n('Completed at'),
      percentWidth: 15,
      isSortable: true,
      render: ({ completed_at }: IocValidationRequestsLine_node$data, { nsdt }: { nsdt: (date: unknown) => string }) => defaultRender(nsdt(completed_at)),
    },
  };

  return (
    <div data-testid="ioc-validation-requests-page">
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: IocValidationRequestsLines_data$data) => data.iocValidationRequests?.edges?.map((edge) => edge?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={requestsLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          entityTypes={[ENTITY_TYPE_IOC_VALIDATION_REQUEST]}
          availableFilterKeys={['status', 'test_kinds', 'created_at', 'completed_at']}
          emptyStateMessage={t_i18n('No validation request yet. Request one with Validate live deployments, on the Deployments tab of an indicator or a security platform.')}
          disableLineSelection
          disableNavigation
          onLineClick={(node: IocValidationRequestsLine_node$data) => setSelected({ id: node.id, name: node.name })}
          actions={canDelete ? (node: IocValidationRequestsLine_node$data) => <RequestDeletion id={node.id} paginationOptions={queryPaginationOptions} /> : undefined}
        />
      )}
      <IocValidationRequestDetails
        requestId={selected?.id ?? null}
        title={selected?.name ?? t_i18n('Validation request')}
        onClose={() => setSelected(null)}
      />
    </div>
  );
};

export default IocValidationRequests;
