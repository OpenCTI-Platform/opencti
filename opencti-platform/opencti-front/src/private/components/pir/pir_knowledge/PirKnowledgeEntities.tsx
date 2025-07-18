import { graphql } from 'react-relay';
import React, { ReactNode } from 'react';
import { PirKnowledgeEntities_SourcesFlaggedFragment$data } from './__generated__/PirKnowledgeEntities_SourcesFlaggedFragment.graphql';
import {
  PirKnowledgeEntitiesSourcesFlaggedListQuery,
  PirKnowledgeEntitiesSourcesFlaggedListQuery$variables,
} from './__generated__/PirKnowledgeEntitiesSourcesFlaggedListQuery.graphql';
import { PirKnowledgeEntities_SourceFlaggedFragment$data } from './__generated__/PirKnowledgeEntities_SourceFlaggedFragment.graphql';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { PaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../../components/dataGrid/DataTable';
import { computeLink } from '../../../../utils/Entity';
import { PaginationOptions } from '../../../../components/list_lines';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useAuth from '../../../../utils/hooks/useAuth';
import { LocalStorage } from '../../../../utils/hooks/useLocalStorageModel';

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
  initialValues: LocalStorage;
  additionalHeaderButtons: ReactNode[];
}

const PirKnowledgeEntities = ({ pirId, localStorage, initialValues, additionalHeaderButtons }: PirKnowledgeEntitiesProps) => {
  const {
    viewStorage,
    helpers,
    localStorageKey,
    paginationOptions,
  } = localStorage;

  const filters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['Stix-Core-Object']);

  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'regardingOf',
        operator: 'eq',
        mode: 'and',
        values: [
          { key: 'id', values: [pirId], operator: 'eq', mode: 'or' },
          { key: 'relationship_type', values: ['in-pir'], operator: 'eq', mode: 'or' },
        ],
      },
    ],
    filterGroups: filters && isFilterGroupNotEmpty(filters)
      ? [filters]
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
          removeSelectAll
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
            return computeLink(e);
          }}
          additionalHeaderButtons={additionalHeaderButtons}
        />
      )}
    </>
  );
};

export default PirKnowledgeEntities;
