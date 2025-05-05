import { graphql, useFragment } from 'react-relay';
import React from 'react';
import { PirKnowledge_SourceFlaggedFragment$data } from '@components/pir/__generated__/PirKnowledge_SourceFlaggedFragment.graphql';
import { PirKnowledgeSourcesFlaggedListQuery, PirKnowledgeSourcesFlaggedListQuery$variables } from './__generated__/PirKnowledgeSourcesFlaggedListQuery.graphql';
import { PirKnowledge_SourcesFlaggedFragment$data } from './__generated__/PirKnowledge_SourcesFlaggedFragment.graphql';
import { PirKnowledgeFragment$key } from './__generated__/PirKnowledgeFragment.graphql';
import { useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { computeLink } from '../../../utils/Entity';

const sourceFlaggedFragment = graphql`
  fragment PirKnowledge_SourceFlaggedFragment on StixRefRelationship {
    id
    pirScore
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
  )
  @refetchable(queryName: "PirsSourcesFlaggedRefetchQuery") {
    stixRefRelationships(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      toId: $toId
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
  ) {
    ...PirKnowledge_SourcesFlaggedFragment
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      toId: $toId
    )
  }
`;

const knowledgeFragment = graphql`
  fragment PirKnowledgeFragment on PIR {
    id
  }
`;

interface PirKnowledgeProps {
  data: PirKnowledgeFragment$key
}

const PirKnowledge = ({ data }: PirKnowledgeProps) => {
  const pir = useFragment(knowledgeFragment, data);
  const LOCAL_STORAGE_KEY = `PIRSourcesFlaggedList-${pir.id}`;

  const initialValues = {
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
  );
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as PirKnowledgeSourcesFlaggedListQuery$variables;

  const queryRef = useQueryLoading<PirKnowledgeSourcesFlaggedListQuery>(
    sourcesFlaggedListQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    pirScore: {
      id: 'pirScore',
      label: 'Score',
      percentWidth: 5,
      isSortable: false,
      render: ({ pirScore }) => defaultRender(`${pirScore}%`),
    },
    from_entity_type: {},
    fromName: {
      id: 'from_name',
      percentWidth: 30,
    },
    from_creator: {
      id: 'from_creator',
      percentWidth: 17,
    },
    from_objectLabel: {},
    from_objectMarking: {},
    from_created_at: {},
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
          entityTypes={['in-pir']}
          searchContextFinal={{ entityTypes: ['in-pir'] }}
          useComputeLink={(e: PirKnowledge_SourceFlaggedFragment$data) => {
            if (!e.from) return '';
            return computeLink(e.from);
          }}
        />
      )}
    </>
  );
};

export default PirKnowledge;
