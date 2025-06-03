import { graphql, useFragment } from 'react-relay';
import React from 'react';
import { PirKnowledge_SourceFlaggedFragment$data } from '@components/pir/__generated__/PirKnowledge_SourceFlaggedFragment.graphql';
import { PirKnowledgeSourcesFlaggedListQuery, PirKnowledgeSourcesFlaggedListQuery$variables } from './__generated__/PirKnowledgeSourcesFlaggedListQuery.graphql';
import { PirKnowledge_SourcesFlaggedFragment$data } from './__generated__/PirKnowledge_SourcesFlaggedFragment.graphql';
import { PirKnowledgeFragment$key } from './__generated__/PirKnowledgeFragment.graphql';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { computeLink } from '../../../utils/Entity';
import FilterIconButton from '../../../components/FilterIconButton';

const sourceFlaggedFragment = graphql`
  fragment PirKnowledge_SourceFlaggedFragment on StixRefRelationship {
    id
    pir_score
    pir_explanations {
      criterion {
        filters
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
  fragment PirKnowledge_SourcesFlaggedFragment on Query
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
  @refetchable(queryName: "PirsSourcesFlaggedRefetchQuery") {
    stixRefRelationships(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      toId: $toId
      relationship_type: $relationship_type
      filters: $filters
    ) @connection(key: "PaginationPirKnowledge_stixRefRelationships") {
      edges {
        node {
          id
          ...PirKnowledge_SourceFlaggedFragment
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
  query PirKnowledgeSourcesFlaggedListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixRefRelationshipsOrdering
    $orderMode: OrderingMode
    $toId: StixRef
    $relationship_type: [String]
    $filters: FilterGroup
  ) {
    ...PirKnowledge_SourcesFlaggedFragment
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

const knowledgeFragment = graphql`
  fragment PirKnowledgeFragment on Pir {
    id
  }
`;

interface PirKnowledgeProps {
  data: PirKnowledgeFragment$key
}

const PirKnowledge = ({ data }: PirKnowledgeProps) => {
  const pir = useFragment(knowledgeFragment, data);
  const LOCAL_STORAGE_KEY = `PirSourcesFlaggedList-${pir.id}`;

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created',
    orderAsc: true,
    openExports: false,
    toId: pir.id,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<
  PirKnowledgeSourcesFlaggedListQuery$variables
  >(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

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
  } as unknown as PirKnowledgeSourcesFlaggedListQuery$variables;

  const queryRef = useQueryLoading<PirKnowledgeSourcesFlaggedListQuery>(
    sourcesFlaggedListQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    pirScore: {
      id: 'pir_score',
      label: 'Score',
      percentWidth: 5,
      isSortable: true,
      render: ({ pir_score }) => defaultRender(`${pir_score}%`),
    },
    from_entity_type: {},
    fromName: {
      id: 'from_name',
      label: 'Source name',
      percentWidth: 25,
    },
    from_creator: {
      id: 'from_creator',
      percentWidth: 10,
    },
    from_objectLabel: {},
    from_objectMarking: {
      isSortable: false,
    },
    pirCriteria: {
      id: 'explanations',
      label: 'Explanations',
      percentWidth: 27,
      render: ({ pir_explanations }) => (
        <div style={{ display: 'flex' }}>
          {pir_explanations.map((e: any) => (
            <FilterIconButton
              key={e.criterion.filters}
              filters={JSON.parse(e.criterion.filters)}
              entityTypes={['Stix-Core-Object']}
              styleNumber={3}
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
          resolvePath={(d: PirKnowledge_SourcesFlaggedFragment$data) => {
            return d.stixRefRelationships?.edges?.map((e) => e?.node);
          }}
          storageKey={LOCAL_STORAGE_KEY}
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
          useComputeLink={(e: PirKnowledge_SourceFlaggedFragment$data) => {
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

export default PirKnowledge;
