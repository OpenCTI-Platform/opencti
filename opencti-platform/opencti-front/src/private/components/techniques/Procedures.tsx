import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { ProceduresLinesPaginationQuery, ProceduresLinesPaginationQuery$variables } from '@components/techniques/__generated__/ProceduresLinesPaginationQuery.graphql';
import { ProceduresLines_data$data } from '@components/techniques/__generated__/ProceduresLines_data.graphql';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import ProcedureCreation from './procedures/ProcedureCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

export const LOCAL_STORAGE_KEY_PROCEDURES = 'procedures';

const procedureFragment = graphql`
  fragment ProceduresLine_node on Procedure {
    id
    entity_type
    name
    description
    x_procedure_type
    x_mitre_platforms
    created
    modified
    confidence
    draftVersion {
      draft_id
      draft_operation
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
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
  }
`;

const proceduresLinesQuery = graphql`
  query ProceduresLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ProceduresOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ProceduresLines_data
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

const proceduresLinesFragment = graphql`
  fragment ProceduresLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ProceduresOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ProceduresLinesRefetchQuery") {
    procedures(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_procedures") {
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

const Procedures: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Procedures | Techniques'));

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
  };
  const {
    viewStorage: { filters },
    helpers: storageHelpers,
    paginationOptions,
  } = usePaginationLocalStorage<ProceduresLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_PROCEDURES,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Procedure', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ProceduresLinesPaginationQuery$variables;

  const dataColumns = {
    name: { percentWidth: 25 },
    x_procedure_type: {},
    x_mitre_platforms: {},
    created: {},
    createdBy: {},
    // ProceduresOrdering has no objectMarking key.
    objectMarking: { isSortable: false },
  };

  const queryRef = useQueryLoading<ProceduresLinesPaginationQuery>(
    proceduresLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationOptions = {
    linesQuery: proceduresLinesQuery,
    linesFragment: proceduresLinesFragment,
    queryRef,
    nodePath: ['procedures', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ProceduresLinesPaginationQuery>;

  return (
    <div data-testid="procedure-page">
      <Breadcrumbs elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Procedures'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          preloadedPaginationProps={preloadedPaginationOptions}
          initialValues={initialValues}
          storageKey={LOCAL_STORAGE_KEY_PROCEDURES}
          contextFilters={contextFilters}
          resolvePath={(data: ProceduresLines_data$data) => data.procedures?.edges?.map((n) => n?.node)}
          lineFragment={procedureFragment}
          exportContext={{ entity_type: 'Procedure' }}
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ProcedureCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
    </div>
  );
};

export default Procedures;
