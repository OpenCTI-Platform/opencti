import React from 'react';
import { graphql } from 'react-relay';
import { Box } from '@mui/material';
import {
  StixCyberObservableNestedEntitiesTablePaginationQuery,
} from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservableNestedEntitiesTablePaginationQuery.graphql';
import {
  StixCyberObservableNestedEntitiesTable_data$data,
} from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservableNestedEntitiesTable_data.graphql';
import StixNestedRefRelationshipPopover from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipPopover';
import { DraftChip } from '@components/common/draft/DraftChip';
import DataTable from '../../../../components/dataGrid/DataTable';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import ItemEntityType from '../../../../components/ItemEntityType';
import ItemIcon from '../../../../components/ItemIcon';
import { StixCyberObservableNestedEntitiesTable_node$data } from './__generated__/StixCyberObservableNestedEntitiesTable_node.graphql';
import { useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import stopEvent from '../../../../utils/domEvent';
import { useComputeLink, ComputeLinkNode } from '../../../../utils/hooks/useAppData';

const LOCAL_STORAGE_KEY = 'StixCyberObservableNestedEntitiesTable';

export const stixCyberObservableNestedEntitiesTableQuery = graphql`
  query StixCyberObservableNestedEntitiesTablePaginationQuery(
    $fromOrToId: String
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixRefRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCyberObservableNestedEntitiesTable_data
    @arguments(
      fromOrToId: $fromOrToId
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const stixCyberObservableNestedEntitiesLineFragment = graphql`
  fragment StixCyberObservableNestedEntitiesTable_node on StixRefRelationship {
    id
    relationship_type
    start_time
    stop_time
    createdBy {
      ... on Identity {
        name
      }
    }
    from {
      ... on BasicObject {
        id
        entity_type
      }
      ... on StixObject {
        draftVersion {
          draft_id
          draft_operation
        }
      }
    }
    to {
      ... on BasicObject {
        id
        entity_type
      }
      ... on StixObject {
        draftVersion {
          draft_id
          draft_operation
        }
        creators {
          id
          name
        }
        ... on AttackPattern {
          name
          description
        }
        ... on Campaign {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
        }
        ... on Individual {
          name
          description
        }
        ... on Organization {
          name
          description
        }
        ... on Sector {
          name
          description
        }
        ... on System {
          name
          description
        }
        ... on Indicator {
          name
        }
        ... on Infrastructure {
          name
        }
        ... on IntrusionSet {
          name
          description
        }
        ... on Position {
          name
          description
        }
        ... on City {
          name
          description
        }
        ... on AdministrativeArea {
          name
          description
        }
        ... on Country {
          name
          description
        }
        ... on Region {
          name
          description
        }
        ... on Malware {
          name
          description
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on ThreatActor {
          name
          description
        }
        ... on Tool {
          name
          description
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          description
        }
        ... on Event {
          name
          description
        }
        ... on Channel {
          name
          description
        }
        ... on Narrative {
          name
          description
        }
        ... on Language {
          name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
          name
        }
        ... on Case {
          name
        }
        ... on StixCyberObservable {
          observable_value
        }
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on Opinion {
          opinion
        }
        ... on ObservedData {
          name
        }
      }
    }
  }
`;

const stixCyberObservableNestedEntitiesTableFragment = graphql`
  fragment StixCyberObservableNestedEntitiesTable_data on Query
  @argumentDefinitions(
    fromOrToId: { type: "String" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixRefRelationshipsOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "StixCyberObservableNestedEntitiesTableRefetchQuery") {
    stixNestedRefRelationships(
      fromOrToId: $fromOrToId
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_stixNestedRefRelationships") {
      edges {
        node {
          id
          ...StixCyberObservableNestedEntitiesTable_node
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

interface StixCyberObservableNestedEntitiesTableProps {
  stixCyberObservableId: string;
  searchTerm: string;
  isInLine: boolean;
}

const StixCyberObservableNestedEntitiesTable: React.FC<StixCyberObservableNestedEntitiesTableProps> = ({
  stixCyberObservableId,
  searchTerm,
  isInLine,
}) => {
  const initialValues = {
    searchTerm: '',
    sortBy: 'relationship_type',
    orderAsc: false,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };
  const computeLink = useComputeLink();
  const { viewStorage, helpers } = usePaginationLocalStorage<StixCyberObservableNestedEntitiesTablePaginationQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Cyber-Observable', viewStorage.filters);
  const queryRef = useQueryLoading(
    stixCyberObservableNestedEntitiesTableQuery,
    {
      fromOrToId: stixCyberObservableId,
      search: searchTerm,
      orderBy: isInLine ? 'relationship_type' : null,
      orderMode: 'desc',
      count: 200,
      filters: contextFilters,
    },
  );

  const preloadedPaginationProps = {
    linesQuery: stixCyberObservableNestedEntitiesTableQuery,
    linesFragment: stixCyberObservableNestedEntitiesTableFragment,
    queryRef,
    nodePath: ['stixNestedRefRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCyberObservableNestedEntitiesTablePaginationQuery>;

  const dataColumns = {
    relationship_type: {
      label: 'Attribute',
      percentWidth: isInLine ? 15 : 10,
      isSortable: true,
      render: (data: StixCyberObservableNestedEntitiesTable_node$data) => (
        <ItemEntityType entityType={data.relationship_type}/>
      ),
    },
    to_entity_type: {
      label: 'Entity type',
      percentWidth: isInLine ? 20 : 10,
      isSortable: false,
      render: (data: StixCyberObservableNestedEntitiesTable_node$data) => (
        <ItemEntityType entityType={data.to?.entity_type || ''}/>
      ),
    },
    name: {
      label: 'Name',
      percentWidth: isInLine ? 35 : 22,
      isSortable: false,
      render: (data: StixCyberObservableNestedEntitiesTable_node$data) => {
        return (
          <>
            {data.to?.name || data.to?.observable_value || data.to?.attribute_abstract || data.to?.content}
            {data.to?.draftVersion && <DraftChip/>}
          </>
        );
      },
    },
    ...(!isInLine && {
      createdBy: {
        label: 'Creator',
        percentWidth: 12,
        isSortable: false,
      },
    }),
    start_time: {
      label: 'First obs.',
      percentWidth: 15,
      isSortable: true,
    },
    stop_time: {
      label: 'Last obs.',
      percentWidth: isInLine ? 15 : 31,
      isSortable: true,
    },
  };

  const getRedirectionLink = (stixObject: StixCyberObservableNestedEntitiesTable_node$data) => {
    const targetObject = stixObject.from?.id === stixCyberObservableId ? stixObject.to : stixObject.from;
    if (targetObject) {
      return computeLink(targetObject as ComputeLinkNode);
    }
    return undefined;
  };

  return (
    <Box style={{
      marginBlockStart: isInLine ? 0 : -25,
    }}
    >
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StixCyberObservableNestedEntitiesTable_data$data) => data.stixNestedRefRelationships?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          lineFragment={stixCyberObservableNestedEntitiesLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          variant={DataTableVariant.inline}
          hideFilters
          hideSearch
          hideHeaders={isInLine}
          disableLineSelection
          getComputeLink={getRedirectionLink}
          icon={(data: StixCyberObservableNestedEntitiesTable_node$data) => <ItemIcon type={data.to?.entity_type}/>}
          actions={(data: StixCyberObservableNestedEntitiesTable_node$data) => {
            return (
              <div style={{ marginLeft: -10 }} onClick={(e) => stopEvent(e)}>
                <StixNestedRefRelationshipPopover
                  stixNestedRefRelationshipId={data.id}
                  paginationOptions={{
                    fromOrToId: stixCyberObservableId,
                    search: searchTerm,
                    orderBy: null,
                    orderMode: 'desc',
                  }}
                />
              </div>
            );
          }}
        />
      )}
    </Box>
  );
};

export default StixCyberObservableNestedEntitiesTable;
