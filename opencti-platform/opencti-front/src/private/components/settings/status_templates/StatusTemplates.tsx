import React from 'react';
import { graphql } from 'react-relay';
import StatusTemplatePopover from '@components/settings/status_templates/StatusTemplatePopover';
import { FactCheckOutlined } from '@mui/icons-material';
import { StatusTemplatesLine_node$data } from '@components/settings/status_templates/__generated__/StatusTemplatesLine_node.graphql';
import StatusTemplateCreation from './StatusTemplateCreation';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { StatusTemplatesLinesPaginationQuery, StatusTemplatesLinesPaginationQuery$variables } from './__generated__/StatusTemplatesLinesPaginationQuery.graphql';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../../components/dataGrid/DataTable';

export const statusTemplatesQuery = graphql`
  query StatusTemplatesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StatusTemplateOrdering
    $orderMode: OrderingMode
  ) {
    ...StatusTemplatesLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

export const statusTemplatesFragment = graphql`
  fragment StatusTemplatesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StatusTemplateOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "StatusTemplatesLinesRefetchQuery") {
    statusTemplates(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_statusTemplates") {
      edges {
        node {
          ...StatusTemplatesLine_node
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

export const StatusTemplatesLineFragment = graphql`
  fragment StatusTemplatesLine_node on StatusTemplate {
    id
    name
    color
    usages
  }
`;

const LOCAL_STORAGE_KEY = 'status-templates';

const StatusTemplates = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Status Templates | Taxonomies | Settings'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<StatusTemplatesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('StatusTemplates', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as StatusTemplatesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<StatusTemplatesLinesPaginationQuery>(
    statusTemplatesQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      percentWidth: 50,
    },
    color: {
      id: 'color',
      percentWidth: 30,
    },
    usages: {
      id: 'usages',
      percentWidth: 20,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: statusTemplatesQuery,
    linesFragment: statusTemplatesFragment,
    queryRef,
    nodePath: ['statusTemplates', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StatusTemplatesLinesPaginationQuery>;

  return (
    <div style={{ marginRight: 200 }} data-testid="status-template-page">
      <LabelsVocabulariesMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Status templates'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.statusTemplates?.edges?.map(({ node }: { node: StatusTemplatesLine_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={StatusTemplatesLineFragment}
          disableNavigation
          disableLineSelection
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(row) => <StatusTemplatePopover data={row} paginationOptions={paginationOptions} />}
          searchContextFinal={{ entityTypes: ['StatusTemplates'] }}
          icon={(data) => <FactCheckOutlined sx={{ color: data.color }} />}
          createButton={<StatusTemplateCreation
            paginationOptions={paginationOptions}
            contextual={false}
            creationCallback={() => { }}
            handleClose={() => { }}
            inputValueContextual={''}
            open={false}
                        />}
        />
      )}
    </div>
  );
};

export default StatusTemplates;
