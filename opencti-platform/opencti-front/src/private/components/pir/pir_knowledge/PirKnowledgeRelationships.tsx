import { graphql } from 'react-relay';
import React from 'react';
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
      render: ({ pir_score }) => <PirRadialScore value={pir_score} />,
    },
    fromType: {
      label: 'Type',
      percentWidth: 10,
    },
    fromName: {
      label: 'Name',
      percentWidth: 25,
    },
    created_at: {
      label: 'First match',
      percentWidth: 8,
    },
    updated_at: {
      label: 'Last match',
      percentWidth: 9,
    },
    from_objectLabel: {
      id: 'from_objectLabel',
      label: 'Labels',
      percentWidth: 9,
    },
    from_objectMarking: {
      label: 'Marking',
      percentWidth: 9,
      isSortable: false,
    },
    pirCriteria: {
      id: 'explanations',
      label: 'Explanations',
      percentWidth: 24,
      render: ({ pir_explanations }) => (
        <div style={{ display: 'flex', gap: theme.spacing(1) }}>
          {pir_explanations.map((e: { criterion: { filters: string } }, i: number) => (
            <PirFiltersDisplay
              key={i}
              filterGroup={JSON.parse(e.criterion.filters)}
              size='small'
            />
          ))}
        </div>
      ),
    },
  };

  return (
    <>
      {queryRef && (
        <DataTable
          disableSelectAll
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
      )}
    </>
  );
};

export default PirKnowledgeRelationships;
