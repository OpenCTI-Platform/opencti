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

import { graphql } from 'react-relay';
import React, { ReactNode } from 'react';
import Tooltip from '@mui/material/Tooltip';
import PirRadialScore from '@components/pir/pir_knowledge/PirRadialScore';
import { useTheme } from '@mui/material/styles';
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
import type { Theme } from '../../../../components/Theme';

const sourceFlaggedFragment = graphql`
  fragment PirKnowledgeEntities_SourceFlaggedFragment on StixDomainObject
  @argumentDefinitions(
    pirId: { type: "ID!"}
  ) {
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
    pirScore(pirId: $pirId)
  }
`;

const sourcesFlaggedFragment = graphql`
  fragment PirKnowledgeEntities_SourcesFlaggedFragment on Query
  @argumentDefinitions(
    pirId: { type: "ID!"}
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixDomainObjectsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirsKnowledgeEntities_SourcesFlaggedRefetchQuery") {
    stixDomainObjects(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "PaginationPirKnowledgeEntities_stixDomainObjects") {
      edges {
        node {
          id
          ...PirKnowledgeEntities_SourceFlaggedFragment
          @arguments(
            pirId: $pirId
          )
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
    $pirId: ID!
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PirKnowledgeEntities_SourcesFlaggedFragment
    @arguments(
      pirId: $pirId
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

  const theme = useTheme<Theme>();

  const filters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['Stix-Domain-Object']);

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
    pirId,
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
    pirScore: {
      id: 'pir_score',
      label: 'Score',
      percentWidth: 6,
      isSortable: true,
      render: ({ pirScore }) => {
        return (
          <Tooltip
            title={(
              <div style={{ display: 'flex', gap: theme.spacing(1), flexWrap: 'wrap' }}>
                {/* {pir_explanations.map((e: { criterion: { filters: string } }, i: number) => ( */}
                {/*  <PirFiltersDisplay */}
                {/*    key={i} */}
                {/*    filterGroup={JSON.parse(e.criterion.filters)} */}
                {/*    size='small' */}
                {/*  /> */}
                {/* ))} */} ## TODO PIR add explanations on hover
              </div>
            )}
          >
            <div>
              <PirRadialScore value={pirScore}/>
            </div>
          </Tooltip>
        );
      },
    },
    entity_type: { percentWidth: 12 },
    name: {},
    createdBy: { isSortable: isRuntimeSort },
    creator: { isSortable: isRuntimeSort },
    objectLabel: { percentWidth: 12 },
    created_at: { percentWidth: 13 },
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
            return d.stixDomainObjects?.edges?.map((e) => e?.node);
          }}
          storageKey={localStorageKey}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: sourcesFlaggedListQuery,
            linesFragment: sourcesFlaggedFragment,
            queryRef,
            nodePath: ['stixDomainObjects', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={sourceFlaggedFragment}
          entityTypes={['Stix-Domain-Object']}
          searchContextFinal={{ entityTypes: ['Stix-Domain-Object'] }}
          currentView={viewStorage.view}
          useComputeLink={(e: PirKnowledgeEntities_SourceFlaggedFragment$data) => {
            if (!e.entity_type) return '';
            return computeLink(e);
          }}
          additionalHeaderButtons={additionalHeaderButtons}
          additionalFilterKeys={[`pir_score.${pirId}`]}
        />
      )}
    </>
  );
};

export default PirKnowledgeEntities;
