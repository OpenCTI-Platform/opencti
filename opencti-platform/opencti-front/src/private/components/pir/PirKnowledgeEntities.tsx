import { graphql } from 'react-relay';
import React from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined } from '@mui/icons-material';
import { RelationManyToMany } from 'mdi-material-ui';
import { PirKnowledgeEntities_SourcesFlaggedFragment$data } from '@components/pir/__generated__/PirKnowledgeEntities_SourcesFlaggedFragment.graphql';
import {
  PirKnowledgeEntitiesSourcesFlaggedListQuery,
  PirKnowledgeEntitiesSourcesFlaggedListQuery$variables,
} from '@components/pir/__generated__/PirKnowledgeEntitiesSourcesFlaggedListQuery.graphql';
import { PirKnowledgeEntities_SourceFlaggedFragment$data } from '@components/pir/__generated__/PirKnowledgeEntities_SourceFlaggedFragment.graphql';
import { isFilterGroupNotEmpty } from '../../../utils/filters/filtersUtils';
import { PaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import { computeLink } from '../../../utils/Entity';
import { useFormatter } from '../../../components/i18n';
import { PaginationOptions } from '../../../components/list_lines';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import useAuth from '../../../utils/hooks/useAuth';

const sourceFlaggedFragment = graphql`
  fragment PirKnowledgeEntities_SourceFlaggedFragment on StixCoreObject {
    id
    entity_type
    created_at
    representative {
      main
    }
    objectLabel {
      id
      color
      value
    }
    creators {
      id
      name
    }
  }
`;

const sourcesFlaggedFragment = graphql`
  fragment PirKnowledgeEntities_SourcesFlaggedFragment on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirsKnowledgeEntities_SourcesFlaggedRefetchQuery") {
    stixCoreObjects(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "PaginationPirKnowledgeEntities_stixCoreObjects") {
      edges {
        node {
          id
          ...PirKnowledgeEntities_SourceFlaggedFragment
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

const sourcesFlaggedListQuery = graphql`
  query PirKnowledgeEntitiesSourcesFlaggedListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PirKnowledgeEntities_SourcesFlaggedFragment
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

interface PirKnowledgeEntitiesProps {
  pirId: string;
  localStorage: PaginationLocalStorage<PaginationOptions>;
  initialValues: any;
}

const PirKnowledgeEntities = ({ pirId, localStorage, initialValues }: PirKnowledgeEntitiesProps) => {
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    helpers,
    localStorageKey,
    paginationOptions,
  } = localStorage;

  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'regardingOf',
        operator: 'eq',
        mode: 'and',
        values: [
          { key: 'id', values: [pirId], operator: 'eq', mode: 'or' },
          { key: 'relationship_type', values: ['in-pir'], operator: 'eq', mode: 'or' },
        ] as unknown as string[], // Workaround for typescript waiting for better solution
      },
    ],
    filterGroups: viewStorage.filters && isFilterGroupNotEmpty(viewStorage.filters)
      ? [viewStorage.filters]
      : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as PirKnowledgeEntitiesSourcesFlaggedListQuery$variables;

  const queryRef = useQueryLoading<PirKnowledgeEntitiesSourcesFlaggedListQuery>(
    sourcesFlaggedListQuery,
    queryPaginationOptions,
  );

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: { percentWidth: 13 },
    name: {},
    createdBy: { isSortable: isRuntimeSort },
    creator: { isSortable: isRuntimeSort },
    objectLabel: {},
    created_at: {},
    objectMarking: { isSortable: isRuntimeSort },
  };

  return (
    <>
      {queryRef && (
        <DataTable
          disableSelectAll
          disableLineSelection
          dataColumns={dataColumns}
          resolvePath={(d: PirKnowledgeEntities_SourcesFlaggedFragment$data) => {
            return d.stixCoreObjects?.edges?.map((e) => e?.node);
          }}
          storageKey={localStorageKey}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: sourcesFlaggedListQuery,
            linesFragment: sourcesFlaggedFragment,
            queryRef,
            nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={sourceFlaggedFragment}
          entityTypes={['Stix-Core-Object']}
          searchContextFinal={{ entityTypes: ['Stix-Core-Object'] }}
          currentView={viewStorage.view}
          useComputeLink={(e: PirKnowledgeEntities_SourceFlaggedFragment$data) => {
            if (!e.entity_type) return '';
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-ignore
            return computeLink(e);
          }}
          additionalHeaderButtons={[
            (<ToggleButton key="entities" value="entities" aria-label="entities">
              <Tooltip title={t_i18n('Entities view')}>
                <LibraryBooksOutlined fontSize="small" color="secondary" />
              </Tooltip>
            </ToggleButton>),
            (<ToggleButton key="relationships" value="relationships" aria-label="relationships">
              <Tooltip title={t_i18n('Relationships view')}>
                <RelationManyToMany color="primary" fontSize="small" />
              </Tooltip>
            </ToggleButton>),
          ]}
        />
      )}
    </>
  );
};

export default PirKnowledgeEntities;
