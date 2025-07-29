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
import Tooltip from '@mui/material/Tooltip';
import React, { useState } from 'react';
import { useTheme } from '@mui/material/styles';
import PirRadialScore from './PirRadialScore';
import PirFiltersDisplay from '../PirFiltersDisplay';
import {
  PirKnowledgeRelationshipsSourcesFlaggedListQuery,
  PirKnowledgeRelationshipsSourcesFlaggedListQuery$variables,
} from './__generated__/PirKnowledgeRelationshipsSourcesFlaggedListQuery.graphql';
import { PirKnowledgeRelationships_SourcesFlaggedFragment$data } from './__generated__/PirKnowledgeRelationships_SourcesFlaggedFragment.graphql';
import { PirKnowledgeRelationships_SourceFlaggedFragment$data } from './__generated__/PirKnowledgeRelationships_SourceFlaggedFragment.graphql';
import { useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { PaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../../components/dataGrid/DataTable';
import { computeLink } from '../../../../utils/Entity';
import { PaginationOptions } from '../../../../components/list_lines';
import { LocalStorage } from '../../../../utils/hooks/useLocalStorageModel';
import type { Theme } from '../../../../components/Theme';

const sourceFlaggedFragment = graphql`
  fragment PirKnowledgeRelationships_SourceFlaggedFragment on StixRefRelationship {
    id
    pir_score
    pir_explanations {
      criterion {
        filters
      }
    }
    created_at
    updated_at
    to {
      ...on Pir {
        name
      }
    }
    from {
      ...on StixCoreObject {
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
    }
  }
`;

const sourcesFlaggedFragment = graphql`
  fragment PirKnowledgeRelationships_SourcesFlaggedFragment on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixRefRelationshipsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    toId: { type: "StixRef" }
    relationship_type: { type: "[String]" }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirsKnowledgeRelationships_SourcesFlaggedRefetchQuery") {
    stixRefRelationships(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      toId: $toId
      relationship_type: $relationship_type
      filters: $filters
    ) @connection(key: "PaginationPirKnowledgeRelationships_stixRefRelationships") {
      edges {
        node {
          id
          ...PirKnowledgeRelationships_SourceFlaggedFragment
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
  query PirKnowledgeRelationshipsSourcesFlaggedListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixRefRelationshipsOrdering
    $orderMode: OrderingMode
    $toId: StixRef
    $relationship_type: [String]
    $filters: FilterGroup
  ) {
    ...PirKnowledgeRelationships_SourcesFlaggedFragment
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      toId: $toId
      relationship_type: $relationship_type
      filters: $filters
    )
  }
`;

interface PirKnowledgeRelationshipsProps {
  pirId: string;
  localStorage: PaginationLocalStorage<PaginationOptions>;
  initialValues: LocalStorage;
}

const PirKnowledgeRelationships = ({
  pirId,
  localStorage,
  initialValues,
}: PirKnowledgeRelationshipsProps) => {
  const theme = useTheme<Theme>();
  const [ref, setRef] = useState<HTMLDivElement | null>(null);

  const {
    viewStorage,
    helpers,
    localStorageKey,
    paginationOptions,
  } = localStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext(
    'in-pir',
    viewStorage.filters,
    undefined,
    ['stix-ref-relationship'],
  );
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
    relationship_type: ['in-pir'],
    toId: pirId,
  } as unknown as PirKnowledgeRelationshipsSourcesFlaggedListQuery$variables;

  const queryRef = useQueryLoading<PirKnowledgeRelationshipsSourcesFlaggedListQuery>(
    sourcesFlaggedListQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    pirScore: {
      id: 'pir_score',
      label: 'Score',
      percentWidth: 6,
      isSortable: true,
      render: ({ pir_score, pir_explanations }) => {
        return (
          <Tooltip
            title={(
              <div style={{ display: 'flex', gap: theme.spacing(1), flexWrap: 'wrap' }}>
                {pir_explanations.map((e: { criterion: { filters: string } }, i: number) => (
                  <PirFiltersDisplay
                    key={i}
                    filterGroup={JSON.parse(e.criterion.filters)}
                    size='small'
                  />
                ))}
              </div>
          )}
          >
            <div>
              <PirRadialScore value={pir_score}/>
            </div>
          </Tooltip>
        );
      },
    },
    fromType: {
      label: 'Type',
      percentWidth: 10,
    },
    fromName: {
      label: 'Name',
      percentWidth: 29,
    },
    created_at: {
      label: 'First match',
      percentWidth: 13,
    },
    updated_at: {
      label: 'Last match',
      percentWidth: 13,
    },
    from_objectLabel: {
      id: 'from_objectLabel',
      label: 'Labels',
      percentWidth: 15,
    },
    from_objectMarking: {
      label: 'Marking',
      percentWidth: 14,
      isSortable: false,
    },
  };

  return (
    <>
      {queryRef && (
        <div style={{ height: 'calc(100vh - 250px)' }} ref={(r) => setRef(r)}>
          <DataTable
            rootRef={ref ?? undefined}
            removeSelectAll
            disableLineSelection
            dataColumns={dataColumns}
            resolvePath={(d: PirKnowledgeRelationships_SourcesFlaggedFragment$data) => {
              return d.stixRefRelationships?.edges?.map((e) => e?.node);
            }}
            storageKey={localStorageKey}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={{
              linesQuery: sourcesFlaggedListQuery,
              linesFragment: sourcesFlaggedFragment,
              queryRef,
              nodePath: ['stixRefRelationships', 'pageInfo', 'globalCount'],
              setNumberOfElements: helpers.handleSetNumberOfElements,
            }}
            lineFragment={sourceFlaggedFragment}
            availableFilterKeys={['fromId', 'fromTypes', 'pir_score']}
            entityTypes={['stix-ref-relationship']}
            searchContextFinal={{ entityTypes: ['stix-ref-relationship'] }}
            currentView={viewStorage.view}
            useComputeLink={(e: PirKnowledgeRelationships_SourceFlaggedFragment$data) => {
              if (!e.from || !e.from.id || !e.from.entity_type) return '';
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-ignore
              return computeLink(e.from);
            }}
          />
        </div>
      )}
    </>
  );
};

export default PirKnowledgeRelationships;
