import React from 'react';
import { graphql } from 'react-relay';
import { PirsListQuery, PirsListQuery$variables } from '@components/pir/__generated__/PirsListQuery.graphql';
import { Pirs_PirsFragment$data } from '@components/pir/__generated__/Pirs_PirsFragment.graphql';
import { Pirs_PirFragment$data } from '@components/pir/__generated__/Pirs_PirFragment.graphql';
import { useTheme } from '@mui/material/styles';
import PirCreation from '@components/pir/PirCreation';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import FilterIconButton from '../../../components/FilterIconButton';
import type { Theme } from '../../../components/Theme';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';

const pirFragment = graphql`
  fragment Pirs_PirFragment on PIR {
    id
    name
    created_at
    updated_at
    entity_type
    creators {
      id
      name
    }
    pirFilters
    pirCriteria {
      id
      weight
      filters
    }
  }
`;

const pirsFragment = graphql`
  fragment Pirs_PirsFragment on Query
  @argumentDefinitions(
      search: { type: "String" }
      count: { type: "Int", defaultValue: 25 }
      cursor: { type: "ID" }
      orderBy: { type: "PIROrdering", defaultValue: name }
      orderMode: { type: "OrderingMode", defaultValue: asc }
      filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PirsRefetchQuery") {
    pirs(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_pirs") {
      edges {
        node {
          id
          ...Pirs_PirFragment
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

const pirsListQuery = graphql`
  query PirsListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: PIROrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...Pirs_PirsFragment
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

const LOCAL_STORAGE_KEY = 'PIRList';

const Pirs = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('PIR'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<PirsListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext(
    'PIR',
    viewStorage.filters,
  );
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as PirsListQuery$variables;

  const queryRef = useQueryLoading<PirsListQuery>(
    pirsListQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 20,
    },
    filters: {
      id: 'filters',
      label: 'Filters',
      percentWidth: 20,
      render: ({ pirFilters }: Pirs_PirFragment$data) => (
        <div style={{ marginLeft: theme.spacing(-0.5) }}>
          <FilterIconButton
            key={pirFilters}
            filters={JSON.parse(pirFilters)}
            entityTypes={['Stix-Core-Object']}
            styleNumber={3}
          />
        </div>
      ),
    },
    criteria: {
      id: 'criteria',
      label: 'Criteria',
      percentWidth: 35,
      render: ({ pirCriteria }: Pirs_PirFragment$data) => (
        <div style={{ marginLeft: theme.spacing(-0.5), display: 'flex' }}>
          {pirCriteria.map((c) => (
            <FilterIconButton
              key={c.filters}
              filters={JSON.parse(c.filters)}
              entityTypes={['Stix-Core-Object']}
              styleNumber={3}
            />
          ))}
        </div>
      ),
    },
    creator: {},
    created_at: {
      id: 'created_at',
      percentWidth: 13,
    },
  };

  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('PIR'), current: true }]} />
      {queryRef && (
        <DataTable
          disableSelectAll
          disableLineSelection
          dataColumns={dataColumns}
          resolvePath={(data: Pirs_PirsFragment$data) => data.pirs?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: pirsListQuery,
            linesFragment: pirsFragment,
            queryRef,
            nodePath: ['pirs', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={pirFragment}
          entityTypes={['PIR']}
          searchContextFinal={{ entityTypes: ['PIR'] }}
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <PirCreation />
            </Security>
          )}
        />
      )}
    </>
  );
};

export default Pirs;
