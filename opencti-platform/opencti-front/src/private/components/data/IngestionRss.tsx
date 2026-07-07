import React, { useContext } from 'react';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import IngestionRssCreation from './ingestionRss/IngestionRssCreation';
import IngestionRssPopover from './ingestionRss/IngestionRssPopover';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth, { UserContext } from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import { INGESTION_MANAGER } from '../../../utils/platformModulesHelper';
import IngestionMenu from './IngestionMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import Button from '../../../components/common/button/Button';
import Security from '../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../utils/hooks/useGranted';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { isNotEmptyField } from '../../../utils/utils';
import IngestionRssImport from '@components/data/IngestionRssImport';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import ItemBoolean from '../../../components/ItemBoolean';
import { IngestionRssLinesDataTableQuery, IngestionRssLinesDataTableQuery$variables } from '@components/data/__generated__/IngestionRssLinesDataTableQuery.graphql';
import { IngestionRssLinesDataTable_data$data } from '@components/data/__generated__/IngestionRssLinesDataTable_data.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';

const LOCAL_STORAGE_KEY = 'ingestionRss';

export const ingestionRssLineFragment = graphql`
  fragment IngestionRssLine_ingestionRss on IngestionRss {
    id
    name
    uri
    ingestion_running
    current_state_date
    last_execution_date
  }
`;

export const ingestionRssLinesQuery = graphql`
  query IngestionRssLinesDataTableQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IngestionRssOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IngestionRssLinesDataTable_data
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

export const ingestionRssLinesFragment = graphql`
  fragment IngestionRssLinesDataTable_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IngestionRssOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IngestionRssLinesDataTableRefetchQuery") {
    ingestionRsss(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_ingestionRsss") {
      edges {
        node {
          id
          ...IngestionRssLine_ingestionRss
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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const IngestionRss = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('RSS Feeds | Ingestion | Data'));
  const { platformModuleHelpers } = useAuth();
  const importFromHubUrl = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings.platform_xtmhub_url}/redirect/opencti_integrations?platform_id=${settings.id}&integrationType=rss_feed`
    : '';
  const initialValues = {
    sortBy: 'name',
    orderAsc: false,
    searchTerm: '',
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<IngestionRssLinesDataTableQuery$variables>(LOCAL_STORAGE_KEY, initialValues);

  const contextFilters = useBuildEntityTypeBasedFilterContext('IngestionRss', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as IngestionRssLinesDataTableQuery$variables;
  const queryRef = useQueryLoading<IngestionRssLinesDataTableQuery>(
    ingestionRssLinesQuery,
    queryPaginationOptions,
  );
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      label: 'Name',
      percentWidth: 20,
      isSortable: true,
    },
    uri: {
      label: 'URL',
      percentWidth: 25,
      isSortable: true,
      render: ({ uri }) => defaultRender(uri),
    },
    ingestion_running: {
      id: 'ingestion_running',
      label: 'Status',
      percentWidth: 15,
      isSortable: false,
      render: ({ ingestion_running }) => (
        <ItemBoolean
          label={ingestion_running ? t_i18n('Active') : t_i18n('Inactive')}
          status={!!ingestion_running}
        />
      ),
    },
    last_execution_date: {
      label: 'Last run',
      percentWidth: 20,
      isSortable: false,
      render: ({ last_execution_date }, helpers) => defaultRender(last_execution_date ? helpers.fd(last_execution_date) : null),
    },
    current_state_date: {
      label: 'Current state',
      percentWidth: 20,
      isSortable: false,
      render: ({ current_state_date }, helpers) => defaultRender(current_state_date ? helpers.fd(current_state_date) : null),
    },
  };
  const preloadedPaginationProps = {
    linesQuery: ingestionRssLinesQuery,
    linesFragment: ingestionRssLinesFragment,
    queryRef,
    nodePath: ['ingestionRsss', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<IngestionRssLinesDataTableQuery>;
  if (!platformModuleHelpers.isIngestionManagerEnable()) {
    return (
      <div className={classes.container}>
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(INGESTION_MANAGER))}
        </Alert>
        <IngestionMenu />
      </div>
    );
  }
  return (
    <div className={classes.container} data-testid="rss-feeds-page">
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('RSS feeds'), current: true }]} />
      <IngestionMenu />
      {queryRef && (
        <DataTable
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          preloadedPaginationProps={preloadedPaginationProps}
          resolvePath={(data: IngestionRssLinesDataTable_data$data) => data.ingestionRsss?.edges?.map((n) => n?.node)}
          dataColumns={dataColumns}
          lineFragment={ingestionRssLineFragment}
          contextFilters={contextFilters}
          entityTypes={['IngestionRss']}
          searchContextFinal={{ entityTypes: ['IngestionRss'] }}
          disableLineSelection
          disableNavigation
          actions={(row) => (
            <Security needs={[INGESTION_SETINGESTIONS]}>
              <IngestionRssPopover
                ingestionRssId={row.id}
                paginationOptions={queryPaginationOptions}
                running={row.ingestion_running}
              />
            </Security>
          )}
          createButton={(
            <Security needs={[INGESTION_SETINGESTIONS]}>
              <>
                <IngestionRssImport paginationOptions={queryPaginationOptions} />
                { isXTMHubAccessible && isNotEmptyField(importFromHubUrl) && (
                  <Button
                    gradient
                    href={importFromHubUrl}
                    target="_blank"
                    title={t_i18n('Import from Hub')}
                  >
                    {t_i18n('Import from Hub')}
                  </Button>
                )}
                <IngestionRssCreation paginationOptions={queryPaginationOptions} />
              </>
            </Security>
          )}
        />
      )}
    </div>
  );
};

export default IngestionRss;
