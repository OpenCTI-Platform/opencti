import React from 'react';
import { graphql } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { MarkingDefinitionsLine_node$data } from '@components/settings/__generated__/MarkingDefinitionsLine_node.graphql';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import { MarkingDefinitionsLinesPaginationQuery } from './__generated__/MarkingDefinitionsLinesPaginationQuery.graphql';
import MarkingDefinitionPopover from './marking_definitions/MarkingDefinitionPopover';
import AccessesMenu from './AccessesMenu';
import { MarkingDefinitionsLines_data$data } from './__generated__/MarkingDefinitionsLines_data.graphql';
import { useFormatter } from '../../../components/i18n';
import MarkingDefinitionCreation from './marking_definitions/MarkingDefinitionCreation';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useSensitiveModifications from '../../../utils/hooks/useSensitiveModifications';
import { Truncate } from '../../../components/dataGrid/dataTableUtils';
import type { DataTableColumn } from '../../../components/dataGrid/dataTableTypes';

const LOCAL_STORAGE_KEY = 'MarkingDefinitions';

export const markingDefinitionsLinesQuery = graphql`
  query MarkingDefinitionsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: MarkingDefinitionsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...MarkingDefinitionsLines_data
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

const markingDefinitionLineFragment = graphql`
  fragment MarkingDefinitionsLine_node on MarkingDefinition {
    id
    standard_id
    definition_type
    definition
    x_opencti_order
    x_opencti_color
    created
    modified
  }
`;

const markingDefinitionsLinesFragment = graphql`
  fragment MarkingDefinitionsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "MarkingDefinitionsOrdering"
      defaultValue: definition
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "MarkingDefinitionsLinesRefetchQuery") {
    markingDefinitions(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_markingDefinitions") {
      edges {
        node {
          id
          entity_type
          ...MarkingDefinitionsLine_node
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

const MarkingDefinitions = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Security: Marking Definitions | Settings'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'definition',
    orderAsc: true,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };
  const { viewStorage: { filters }, helpers, paginationOptions } = usePaginationLocalStorage<MarkingDefinitionsLinesPaginationQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('Marking-Definition', filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters };

  const definitionTypeRender: DataTableColumn['render'] = (
    data: MarkingDefinitionsLine_node$data,
  ) => {
    const { standard_id, definition_type } = data;
    const { isSensitive } = useSensitiveModifications('markings', standard_id);
    return (
      <Tooltip title={definition_type}>
        <div style={{ display: 'flex' }}>
          <Truncate>{definition_type}</Truncate>
          {isSensitive && <DangerZoneChip />}
        </div>
      </Tooltip>
    );
  };

  const dataColumns = {
    definition_type: {
      percentWidth: 25,
      render: definitionTypeRender,
    },
    definition: { percentWidth: 25 },
    x_opencti_color: { percentWidth: 15 },
    x_opencti_order: { percentWidth: 15 },
    created: { percentWidth: 20 },
  };

  const queryRef = useQueryLoading(
    markingDefinitionsLinesQuery,
    { ...queryPaginationOptions, count: 25 },
  );

  const preloadedPaginationProps = {
    linesQuery: markingDefinitionsLinesQuery,
    linesFragment: markingDefinitionsLinesFragment,
    queryRef,
    nodePath: ['markingDefinitions', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<MarkingDefinitionsLinesPaginationQuery>;

  return (
    <div style={{ paddingRight: '200px' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Security') },
        { label: t_i18n('Marking definitions'), current: true },
      ]}
      />
      <AccessesMenu/>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: MarkingDefinitionsLines_data$data) => data.markingDefinitions?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={markingDefinitionLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(markingDefinition) => (
            <MarkingDefinitionPopover
              markingDefinition={markingDefinition}
              paginationOptions={queryPaginationOptions}
            />
          )}
          entityTypes={['Marking-Definition']}
          searchContextFinal={{ entityTypes: ['Marking-Definition'] }}
          disableNavigation
          disableToolBar
          disableSelectAll
          canToggleLine={false}
          createButton={<MarkingDefinitionCreation paginationOptions={queryPaginationOptions}/>}
        />
      )}
    </div>
  );
};

export default MarkingDefinitions;
