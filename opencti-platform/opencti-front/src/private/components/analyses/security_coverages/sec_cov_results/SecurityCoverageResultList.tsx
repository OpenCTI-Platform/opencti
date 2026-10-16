import { graphql } from 'react-relay';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from '../../../../../components/common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import DataTable from '../../../../../components/dataGrid/DataTable';
import { DataTableProps, DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../../utils/hooks/usePreloadedPaginationFragment';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import { SecurityCoverageResultToEdit } from './SecurityCoverageResultForm-utils';
import {
  SecurityCoverageResultListLinesQuery,
  SecurityCoverageResultListLinesQuery$variables,
} from './__generated__/SecurityCoverageResultListLinesQuery.graphql';
import { SecurityCoverageResultListLines_data$data } from './__generated__/SecurityCoverageResultListLines_data.graphql';

const LOCAL_STORAGE_KEY = 'SecurityCoverageResultList';
const ENTITY_TYPES = ['Security-Coverage-Result'];

const INITIAL_VALUES = {
  searchTerm: '',
  sortBy: 'name',
  orderAsc: true,
  numberOfElements: {
    number: 0,
    symbol: '',
  },
};

const securityCoverageResultListLinesQuery = graphql`
  query SecurityCoverageResultListLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: SecurityCoverageResultOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SecurityCoverageResultListLines_data
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

const securityCoverageResultListLinesFragment = graphql`
  fragment SecurityCoverageResultListLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "SecurityCoverageResultOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "SecurityCoverageResultListLinesRefetchQuery") {
    securityCoverageResults(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_securityCoverageResults") {
      edges {
        node {
          id
          ...SecurityCoverageResultListLine_node
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

const securityCoverageResultListLineFragment = graphql`
  fragment SecurityCoverageResultListLine_node on SecurityCoverageResult {
    id
    entity_type
    name
    created_at
    draftVersion {
      draft_id
      draft_operation
    }
    representative {
      main
    }
    coverage_information {
      coverage_name
      coverage_score
    }
    createdBy {
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
`;

const DATA_COLUMNS: DataTableProps['dataColumns'] = {
  name: { percentWidth: 30 },
  coverage: { percentWidth: 15 },
  objectLabel: { percentWidth: 15 },
  createdBy: { percentWidth: 15, isSortable: false },
  objectMarking: { percentWidth: 10 },
  created_at: { percentWidth: 15 },
};

interface SecurityCoverageResultListProps {
  securityCoverageId: string;
  // Results of the security coverage, holding the values used to fill the form.
  results: readonly SecurityCoverageResultToEdit[];
  onSelect: (result: SecurityCoverageResultToEdit) => void;
  onCancel: () => void;
}

const SecurityCoverageResultList = ({
  securityCoverageId,
  results,
  onSelect,
  onCancel,
}: SecurityCoverageResultListProps) => {
  const { t_i18n } = useFormatter();

  const {
    viewStorage: { filters },
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<SecurityCoverageResultListLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    INITIAL_VALUES,
    true,
  );

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ENTITY_TYPES);

  // Only the results of this security coverage can be updated.
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'resultOf', values: [securityCoverageId], operator: 'eq', mode: 'or' },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as SecurityCoverageResultListLinesQuery$variables;

  const queryRef = useQueryLoading<SecurityCoverageResultListLinesQuery>(
    securityCoverageResultListLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: securityCoverageResultListLinesQuery,
    linesFragment: securityCoverageResultListLinesFragment,
    queryRef,
    nodePath: ['securityCoverageResults', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SecurityCoverageResultListLinesQuery>;

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={DATA_COLUMNS}
          resolvePath={(data: SecurityCoverageResultListLines_data$data) => data.securityCoverageResults?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={INITIAL_VALUES}
          lineFragment={securityCoverageResultListLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          contextFilters={contextFilters}
          entityTypes={ENTITY_TYPES}
          variant={DataTableVariant.inline}
          disableNavigation
          disableLineSelection
          disableToolBar
          actionsColumnWidth={100}
          actions={(row: { id: string }) => {
            const result = results.find((r) => r.id === row.id);
            return (
              <Button
                size="small"
                disabled={!result}
                onClick={() => result && onSelect(result)}
              >
                {t_i18n('Update')}
              </Button>
            );
          }}
        />
      )}
      <FormButtonContainer>
        <Button variant="tertiary" onClick={onCancel}>
          {t_i18n('Cancel')}
        </Button>
      </FormButtonContainer>
    </>
  );
};

export default SecurityCoverageResultList;
