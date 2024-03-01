import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { SearchStixCoreObjectLine_node$data } from '@components/search/__generated__/SearchStixCoreObjectLine_node.graphql';
import {
  SearchStixCoreObjectsLinesPaginationQuery,
  SearchStixCoreObjectsLinesPaginationQuery$variables,
} from '@components/search/__generated__/SearchStixCoreObjectsLinesPaginationQuery.graphql';
import { SearchStixCoreObjectsLines_data$key } from '@components/search/__generated__/SearchStixCoreObjectsLines_data.graphql';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { SearchStixCoreObjectLine, SearchStixCoreObjectLineDummy } from './SearchStixCoreObjectLine';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../components/list_lines';

const nbOfRowsToLoad = 50;

interface SearchStixCoreObjectsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: SearchStixCoreObjectsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<SearchStixCoreObjectsLinesPaginationQuery>;
  selectedElements: Record<string, SearchStixCoreObjectLine_node$data>;
  deSelectedElements: Record<string, SearchStixCoreObjectLine_node$data>;
  onToggleEntity: (
    entity: SearchStixCoreObjectLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
  redirectionMode?: string;
}

export const searchStixCoreObjectsLinesQuery = graphql`
  query SearchStixCoreObjectsLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SearchStixCoreObjectsLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const searchStixCoreObjectsLinesSearchQuery = graphql`
  query SearchStixCoreObjectsLinesSearchQuery(
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjects(types: $types, search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          created_at
          updated_at
          ... on AttackPattern {
            name
            description
            aliases
          }
          ... on Campaign {
            name
            description
            aliases
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
            explanation
          }
          ... on Report {
            name
            description
          }
          ... on Grouping {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
            x_opencti_aliases
          }
          ... on Individual {
            name
            description
            x_opencti_aliases
          }
          ... on Organization {
            name
            description
            x_opencti_aliases
          }
          ... on Sector {
            name
            description
            x_opencti_aliases
          }
          ... on System {
            name
            description
            x_opencti_aliases
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            aliases
            description
          }
          ... on Position {
            name
            description
            x_opencti_aliases
          }
          ... on City {
            name
            description
            x_opencti_aliases
          }
          ... on AdministrativeArea {
            name
            description
            x_opencti_aliases
          }
          ... on Country {
            name
            description
            x_opencti_aliases
          }
          ... on Region {
            name
            description
            x_opencti_aliases
          }
          ... on Malware {
            name
            aliases
            description
          }
          ... on ThreatActor {
            name
            aliases
            description
          }
          ... on Tool {
            name
            aliases
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            aliases
            description
          }
          ... on Event {
            name
            aliases
            description
          }
          ... on Channel {
            name
            aliases
            description
          }
          ... on Narrative {
            name
            aliases
            description
          }
          ... on Language {
            name
            aliases
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
          ... on StixFile {
            x_opencti_additional_names
          }
          ... on IPv4Addr {
            countries {
              edges {
                node {
                  name
                  x_opencti_aliases
                }
              }
            }
          }
          ... on IPv6Addr {
            countries {
              edges {
                node {
                  name
                  x_opencti_aliases
                }
              }
            }
          }
          createdBy {
            ... on Identity {
              name
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          objectLabel {
            id
            value
            color
          }
          creators {
            id
            name
          }
          containersNumber {
            total
          }
        }
      }
    }
  }
`;

export const searchStixCoreObjectsLinesFragment = graphql`
  fragment SearchStixCoreObjectsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SearchStixCoreObjectsLinesRefetchQuery") {
    globalSearch(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_globalSearch") {
      edges {
        node {
          id
          entity_type
          created_at
          createdBy {
            ... on Identity {
              name
            }
          }
          creators {
            id
            name
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...SearchStixCoreObjectLine_node
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

const SearchStixCoreObjectsLines: FunctionComponent<SearchStixCoreObjectsLinesProps> = ({
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  paginationOptions,
  setNumberOfElements,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  SearchStixCoreObjectsLinesPaginationQuery,
  SearchStixCoreObjectsLines_data$key
  >({
    linesQuery: searchStixCoreObjectsLinesQuery,
    linesFragment: searchStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['globalSearch', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.globalSearch?.edges ?? []}
      globalCount={
        data?.globalSearch?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={SearchStixCoreObjectLine}
      DummyLineComponent={SearchStixCoreObjectLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
      paginationOptions={paginationOptions}
    />
  );
};

export default SearchStixCoreObjectsLines;
