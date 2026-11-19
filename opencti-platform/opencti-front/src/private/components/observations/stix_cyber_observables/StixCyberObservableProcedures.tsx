import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import {
  FilterGroup,
  StixCyberObservableProceduresPaginationQuery,
  StixCyberObservableProceduresPaginationQuery$variables,
} from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservableProceduresPaginationQuery.graphql';
import { StixCyberObservableProcedures_data$data } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservableProcedures_data.graphql';
import { procedureFragment } from '@components/techniques/Procedures';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'StixCyberObservableProcedures';

// A procedure refers to an observable through a has-observable relationship, or runs it as its command.
export const buildObservableProceduresFilters = (observableId: string): FilterGroup => ({
  mode: 'or',
  filterGroups: [],
  filters: [
    {
      key: ['regardingOf'],
      values: [
        { key: 'id', values: [observableId] },
        { key: 'relationship_type', values: ['has-observable'] },
      ],
      operator: 'eq',
      mode: 'or',
    },
    { key: ['procedureCommand'], values: [observableId], operator: 'eq', mode: 'or' },
  ],
});

const stixCyberObservableProceduresQuery = graphql`
  query StixCyberObservableProceduresPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ProceduresOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCyberObservableProcedures_data
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

const stixCyberObservableProceduresFragment = graphql`
  fragment StixCyberObservableProcedures_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ProceduresOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "StixCyberObservableProceduresRefetchQuery") {
    procedures(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_observable_procedures") {
      edges {
        node {
          id
          ...ProceduresLine_node
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

interface StixCyberObservableProceduresProps {
  observableId: string;
}

const StixCyberObservableProcedures: FunctionComponent<StixCyberObservableProceduresProps> = ({
  observableId,
}) => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
  };
  const { helpers, paginationOptions } = usePaginationLocalStorage<StixCyberObservableProceduresPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  // The observable filter always applies; the stored sort and page size drive the query.
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: buildObservableProceduresFilters(observableId),
  } as unknown as StixCyberObservableProceduresPaginationQuery$variables;
  const queryRef = useQueryLoading<StixCyberObservableProceduresPaginationQuery>(
    stixCyberObservableProceduresQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: stixCyberObservableProceduresQuery,
    linesFragment: stixCyberObservableProceduresFragment,
    queryRef,
    nodePath: ['procedures', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCyberObservableProceduresPaginationQuery>;

  const dataColumns = {
    name: { percentWidth: 25 },
    x_procedure_type: {},
    x_mitre_platforms: {},
    created: {},
    createdBy: {},
    // ProceduresOrdering has no objectMarking key.
    objectMarking: { isSortable: false },
  };

  return (
    <Card title={t_i18n('Procedures')}>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StixCyberObservableProcedures_data$data) => data.procedures?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          lineFragment={procedureFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          variant={DataTableVariant.inline}
          hideFilters
          hideSearch
          disableLineSelection
        />
      )}
    </Card>
  );
};

export default StixCyberObservableProcedures;
