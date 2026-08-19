import { useState } from 'react';
import ListLines from 'src/components/list_lines/ListLines';
import ListLinesContent from 'src/components/list_lines/ListLinesContent';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from 'src/utils/filters/filtersUtils';
import { QueryRenderer } from 'src/relay/environment';
import SecurityCoverageEntityLine from '../SecurityCoverageEntityLine';
import Loader, { LoaderVariant } from 'src/components/Loader';
import { graphql } from 'react-relay';
import useFiltersState from 'src/utils/filters/useFiltersState';
import { StixCoreObjectNode } from './securityCoverageCreation-types';

interface SelectCoveredEntityStepProps {
  onSelectEntity: (entity: StixCoreObjectNode) => void;
  selectedEntity: StixCoreObjectNode | null;
}
interface EntitiesQueryProps {
  stixCoreObjects?: {
    edges: Array<{ node: StixCoreObjectNode }>;
  };
}

// Query for fetching entities to be covered
const securityCoverageEntitiesQuery = graphql`
  query SelectCoveredEntityStepQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCoreObjects") {
      edges {
        node {
          id
          standard_id
          entity_type
          created_at
          representative {
            main
          }
          createdBy {
            ... on Identity {
              id
              name
            }
          }
          creators {
            id
            name
          }
          objectLabel {
            id
            value
            color
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
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

// Default entity types for coverage
const DEFAULT_ENTITY_TYPES = [
  'Report',
  'Grouping',
  'Case-Incident',
  'Intrusion-Set',
  'Campaign',
  'Incident',
];

const initialFilters = {
  ...emptyFilterGroup,
  filters: [
    {
      key: 'regardingOf',
      operator: 'not_eq',
      values: [
        {
          key: 'relationship_type',
          values: [
            'object-covered',
          ],
        },
      ],
      mode: 'or',
    },
  ],
};

const COLUMNS = {
  entity_type: {
    label: 'Type',
    width: '12%',
    isSortable: true,
  },
  value: {
    label: 'Value',
    width: '28%',
    isSortable: false,
  },
  createdBy: {
    label: 'Author',
    width: '12%',
    isSortable: true,
  },
  objectLabel: {
    label: 'Labels',
    width: '22%',
    isSortable: false,
  },
  objectMarking: {
    label: 'Marking',
    width: '16%',
    isSortable: false,
  },
};

const SelectCoveredEntityStep = (
  {
    onSelectEntity,
    selectedEntity,
  }: SelectCoveredEntityStepProps) => {
  // Entity selection state - not persisted to local storage or URL
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [orderAsc, setOrderAsc] = useState(false);
  const [filters, helpers] = useFiltersState(initialFilters);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Domain-Object', filters);
  const handleSort = (field: string, order: boolean) => {
    setSortBy(field);
    setOrderAsc(order);
  };
  const handleSearch = (value: string) => {
    setSearchTerm(value);
  };

  const queryPaginationOptions = {
    types: DEFAULT_ENTITY_TYPES,
    search: searchTerm,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc' as 'asc' | 'desc',
    count: 50,
    cursor: null,
  };

  return (
    <>
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={COLUMNS}
        handleSort={handleSort}
        handleSearch={handleSearch}
        handleAddFilter={helpers.handleAddSingleValueFilter}
        handleRemoveFilter={helpers.handleRemoveRepresentationFilter}
        handleSwitchFilter={helpers.handleSwitchGlobalMode}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={queryPaginationOptions}
        numberOfElements={{ number: 0, symbol: '' }}
        availableFilterKeys={['entity_type', 'objectLabel', 'createdBy', 'objectMarking', 'created_start_date', 'created_end_date', 'created_at_start_date', 'created_at_end_date']}
        availableEntityTypes={DEFAULT_ENTITY_TYPES}
        noPadding={true}
        disableCards={true}
        noHeaders={false}
        iconExtension
      >
        <QueryRenderer
          query={securityCoverageEntitiesQuery}
          variables={queryPaginationOptions}
          render={(renderProps: { props: EntitiesQueryProps | null }) => {
            const { props } = renderProps;
            if (!props || !props.stixCoreObjects) {
              return <Loader variant={LoaderVariant.inElement} />;
            }
            return (
              <ListLinesContent
                initialLoading={false}
                loadMore={() => {}}
                hasMore={() => false}
                isLoading={() => false}
                dataList={props.stixCoreObjects.edges.slice(0, 50)}
                globalCount={Math.min(props.stixCoreObjects.edges.length, 50)}
                LineComponent={SecurityCoverageEntityLine}
                DummyLineComponent={() => null}
                dataColumns={COLUMNS}
                paginationOptions={queryPaginationOptions}
                selectedElements={{}}
                selectAll={false}
                onToggleEntity={onSelectEntity}
                onLabelClick={helpers.handleAddSingleValueFilter}
                redirectionMode={undefined}
                selectedEntity={selectedEntity}
              />
            );
          }}
        />
      </ListLines>
    </>
  );
};

export default SelectCoveredEntityStep;
