import { graphql } from 'react-relay';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Stack } from '@mui/material';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { emptyFilterGroup, isFilterGroupNotEmpty, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { PATH_INDICATOR, PATH_SECURITY_PLATFORM } from '@components/common/routes/paths';
import { DeploymentStatusChip, ValidationStatusChip } from './DisseminationStatusChips';
import DeployedOnActions from './DeployedOnActions';
import { RELATION_DEPLOYED_ON } from './disseminationAssuranceUtils';
import type { DeployedOnRelationships_node$data } from './__generated__/DeployedOnRelationships_node.graphql';
import type { DeployedOnRelationshipsLines_data$data } from './__generated__/DeployedOnRelationshipsLines_data.graphql';
import type {
  DeployedOnRelationshipsLinesPaginationQuery,
  DeployedOnRelationshipsLinesPaginationQuery$variables,
} from './__generated__/DeployedOnRelationshipsLinesPaginationQuery.graphql';

const deployedOnRelationshipsQuery = graphql`
  query DeployedOnRelationshipsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DeployedOnRelationshipsLines_data
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

const deployedOnRelationshipsLinesFragment = graphql`
  fragment DeployedOnRelationshipsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreRelationshipsOrdering", defaultValue: last_sync_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DeployedOnRelationshipsLinesRefetchQuery") {
    stixCoreRelationships(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_deployedOn_stixCoreRelationships") {
      edges {
        node {
          id
          ...DeployedOnRelationships_node
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

export const deployedOnRelationshipsLineFragment = graphql`
  fragment DeployedOnRelationships_node on StixCoreRelationship {
    id
    standard_id
    entity_type
    relationship_type
    revoked
    created_at
    deployment_status
    external_id
    deployed_at
    last_sync_at
    removed_at
    hit_count
    last_hit_at
    validation_status
    last_validation_at
    error_message
    from {
      ... on Indicator {
        id
        entity_type
        name
        pattern_type
        revoked
        valid_until
      }
    }
    to {
      ... on SecurityPlatform {
        id
        entity_type
        name
        security_platform_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
  }
`;

export type DeployedOnSide = 'indicator' | 'platform';

interface DeployedOnRelationshipsProps {
  /** Indicator page lists the platforms, Security Platform page lists the indicators. */
  side: DeployedOnSide;
  entityId: string;
}

const DeployedOnRelationships = ({ side, entityId }: DeployedOnRelationshipsProps) => {
  const { t_i18n, nsdt, n } = useFormatter();
  const canUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const LOCAL_STORAGE_KEY = `deployed-on-${side}-${entityId}`;
  const initialValues = {
    searchTerm: '',
    sortBy: 'last_sync_at',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { paginationOptions, viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<DeployedOnRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );
  const userFilters = useBuildEntityTypeBasedFilterContext('stix-core-relationship', viewStorage.filters);
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'relationship_type', values: [RELATION_DEPLOYED_ON] },
      { key: side === 'indicator' ? 'fromId' : 'toId', values: [entityId] },
    ],
    filterGroups: isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DeployedOnRelationshipsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<DeployedOnRelationshipsLinesPaginationQuery>(deployedOnRelationshipsQuery, queryPaginationOptions);
  const preloadedPaginationProps = {
    linesQuery: deployedOnRelationshipsQuery,
    linesFragment: deployedOnRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DeployedOnRelationshipsLinesPaginationQuery>;

  const counterpartColumn: DataTableProps['dataColumns'] = side === 'indicator'
    ? {
        platform: {
          id: 'platform',
          label: t_i18n('Security platform'),
          percentWidth: 20,
          isSortable: false,
          render: ({ to }: DeployedOnRelationships_node$data) => defaultRender(to?.name ?? t_i18n('Restricted')),
        },
      }
    : {
        indicator: {
          id: 'indicator',
          label: t_i18n('Indicator'),
          percentWidth: 20,
          isSortable: false,
          render: ({ from }: DeployedOnRelationships_node$data) => defaultRender(from?.name ?? t_i18n('Restricted')),
        },
      };

  const dataColumns: DataTableProps['dataColumns'] = {
    ...counterpartColumn,
    deployment_status: {
      id: 'deployment_status',
      label: t_i18n('Deployment status'),
      percentWidth: 12,
      isSortable: true,
      render: ({ deployment_status, error_message }: DeployedOnRelationships_node$data) => {
        if (deployment_status === 'failed' && error_message) {
          return (
            <Tooltip>
              <TooltipTrigger asChild>
                <span><DeploymentStatusChip status={deployment_status} /></span>
              </TooltipTrigger>
              <TooltipContent>{error_message}</TooltipContent>
            </Tooltip>
          );
        }
        return <DeploymentStatusChip status={deployment_status} />;
      },
    },
    external_id: {
      id: 'external_id',
      label: t_i18n('External id'),
      percentWidth: 13,
      isSortable: false,
      render: ({ external_id }: DeployedOnRelationships_node$data) => defaultRender(external_id),
    },
    last_sync_at: {
      id: 'last_sync_at',
      label: t_i18n('Last synchronization'),
      percentWidth: 12,
      isSortable: true,
      render: ({ last_sync_at }: DeployedOnRelationships_node$data) => defaultRender(nsdt(last_sync_at)),
    },
    hit_count: {
      id: 'hit_count',
      label: t_i18n('Hits'),
      percentWidth: 7,
      isSortable: true,
      render: ({ hit_count }: DeployedOnRelationships_node$data) => defaultRender(n(hit_count ?? 0)),
    },
    last_hit_at: {
      id: 'last_hit_at',
      label: t_i18n('Last hit'),
      percentWidth: 12,
      isSortable: true,
      render: ({ last_hit_at }: DeployedOnRelationships_node$data) => defaultRender(nsdt(last_hit_at)),
    },
    validation_status: {
      id: 'validation_status',
      label: t_i18n('Validation status'),
      percentWidth: 12,
      isSortable: true,
      render: ({ validation_status }: DeployedOnRelationships_node$data) => <ValidationStatusChip status={validation_status} />,
    },
    last_validation_at: {
      id: 'last_validation_at',
      label: t_i18n('Last validation'),
      percentWidth: 12,
      isSortable: true,
      render: ({ last_validation_at }: DeployedOnRelationships_node$data) => defaultRender(nsdt(last_validation_at)),
    },
  };

  return (
    <div data-testid={`deployed-on-${side}`}>
      {queryRef && (
        <DataTable
          variant={DataTableVariant.inline}
          dataColumns={dataColumns}
          resolvePath={(data: DeployedOnRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((edge) => edge?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={deployedOnRelationshipsLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          availableFilterKeys={['deployment_status', 'validation_status', 'last_sync_at', 'last_hit_at', 'hit_count', 'objectMarking']}
          disableLineSelection
          icon={() => (
            <Stack direction="row" alignItems="center">
              <ItemIcon type={side === 'indicator' ? 'SecurityPlatform' : 'Indicator'} />
            </Stack>
          )}
          getComputeLink={(node: DeployedOnRelationships_node$data) => {
            if (side === 'indicator') return node.to?.id ? PATH_SECURITY_PLATFORM(node.to.id) : undefined;
            return node.from?.id ? PATH_INDICATOR(node.from.id) : undefined;
          }}
          actions={canUpdate ? (node: DeployedOnRelationships_node$data) => (
            <DeployedOnActions id={node.id} deploymentStatus={node.deployment_status} revoked={node.revoked} />
          ) : undefined}
        />
      )}
    </div>
  );
};

export default DeployedOnRelationships;
