import React, { Suspense, useLayoutEffect, useState } from 'react';
import { graphql } from 'react-relay';
import Button from '@common/button/Button';
import { BarChartOutlined } from '@mui/icons-material';
import { Text } from '@filigran/design-system';
import HuntsFirstUse from './HuntsFirstUse';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { Hunts_HuntFragment$data } from './__generated__/Hunts_HuntFragment.graphql';
import { Hunts_HuntsFragment$data } from './__generated__/Hunts_HuntsFragment.graphql';
import { HuntsListQuery, HuntsListQuery$variables } from './__generated__/HuntsListQuery.graphql';
import HuntCreation from './HuntCreation';
import HuntStatistics from './HuntStatistics';
import { HuntPackExportButton, HuntPackImportButton } from './HuntPack';
import HuntQuickStartMenu from './HuntQuickStartMenu';
import { HuntSourceKindChip, HuntStatusChip } from './HuntChips';
import { huntScheduleMode } from './hunt-schedule-utils';
import { useHuntScheduleText } from './HuntSchedulePreview';
import { HUNT_ENTITY_TYPE, huntTypeLabel } from './hunt-utils';
import { unscrolledTop } from './hunt-layout-utils';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { emptyFilterGroup, isFilterGroupNotEmpty, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';

export const huntsLineFragment = graphql`
  fragment Hunts_HuntFragment on Hunt {
    id
    standard_id
    entity_type
    name
    representative {
      main
    }
    hunt_type
    hunt_status
    hunt_source_kind
    hunt_schedule
    last_run_at
    last_run_status
    last_hits_count
    last_new_hits_count
    next_run_at
    created
    created_at
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
    objectLabel {
      id
      value
      color
    }
  }
`;

export const huntsLinesFragment = graphql`
  fragment Hunts_HuntsFragment on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "HuntsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "HuntsRefetchQuery") {
    hunts(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_hunts") {
      edges {
        node {
          id
          ...Hunts_HuntFragment
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

export const huntsListQuery = graphql`
  query HuntsListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: HuntsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...Hunts_HuntsFragment
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

export const LOCAL_STORAGE_KEY = 'hunts';
const CHARTS_STORAGE_KEY = 'hunts-show-charts';
const MIN_TABLE_HEIGHT = 360;
const PAGE_BOTTOM_PADDING = 20;

/** Space left in the viewport under the statistics, so the data table keeps its own scroll. */
const useRemainingHeight = (element: HTMLDivElement | null, watched: HTMLDivElement | null) => {
  const [height, setHeight] = useState(MIN_TABLE_HEIGHT);
  useLayoutEffect(() => {
    if (!element) {
      return undefined;
    }
    const compute = () => {
      setHeight(Math.max(MIN_TABLE_HEIGHT, window.innerHeight - unscrolledTop(element) - PAGE_BOTTOM_PADDING));
    };
    compute();
    window.addEventListener('resize', compute);
    const observer = watched ? new ResizeObserver(compute) : null;
    if (watched && observer) {
      observer.observe(watched);
    }
    return () => {
      window.removeEventListener('resize', compute);
      observer?.disconnect();
    };
  }, [element, watched]);
  return height;
};

const Hunts = () => {
  const { t_i18n, n } = useFormatter();
  const scheduleText = useHuntScheduleText();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Hunts | Defense'));
  const [showCharts, setShowCharts] = useState(() => localStorage.getItem(CHARTS_STORAGE_KEY) !== 'false');
  const [statisticsElement, setStatisticsElement] = useState<HTMLDivElement | null>(null);
  const [tableElement, setTableElement] = useState<HTMLDivElement | null>(null);
  const tableHeight = useRemainingHeight(tableElement, statisticsElement);

  const toggleCharts = () => {
    setShowCharts((current) => {
      localStorage.setItem(CHARTS_STORAGE_KEY, String(!current));
      return !current;
    });
  };

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['hunt_status', 'hunt_type'], [HUNT_ENTITY_TYPE]),
    },
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<HuntsListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext(HUNT_ENTITY_TYPE, viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as HuntsListQuery$variables;
  const queryRef = useQueryLoading<HuntsListQuery>(huntsListQuery, queryPaginationOptions);

  const dataColumns: DataTableProps['dataColumns'] = {
    name: { percentWidth: 22 },
    hunt_status: {
      id: 'hunt_status',
      label: 'Status',
      percentWidth: 8,
      isSortable: true,
      render: ({ hunt_status }: Hunts_HuntFragment$data) => <HuntStatusChip value={hunt_status} />,
    },
    hunt_type: {
      id: 'hunt_type',
      label: 'Type',
      percentWidth: 10,
      isSortable: true,
      render: ({ hunt_type }: Hunts_HuntFragment$data) => defaultRender(t_i18n(huntTypeLabel(hunt_type))),
    },
    hunt_source_kind: {
      id: 'hunt_source_kind',
      label: 'Origin',
      percentWidth: 8,
      isSortable: true,
      render: ({ hunt_source_kind }: Hunts_HuntFragment$data) => <HuntSourceKindChip value={hunt_source_kind} />,
    },
    hunt_schedule: {
      id: 'hunt_schedule',
      label: 'Schedule',
      percentWidth: 11,
      isSortable: true,
      render: ({ hunt_schedule }: Hunts_HuntFragment$data) => {
        const mode = huntScheduleMode(hunt_schedule);
        if (mode === 'cron') {
          return defaultRender(scheduleText(hunt_schedule));
        }
        return defaultRender(t_i18n(mode === 'standing' ? 'Standing hunt' : 'Manual'));
      },
    },
    last_run_at: {
      id: 'last_run_at',
      label: 'Last run',
      percentWidth: 10,
      isSortable: true,
      render: ({ last_run_at }: Hunts_HuntFragment$data, { fd }: { fd: (date: string | null | undefined) => string }) => defaultRender(fd(last_run_at)),
    },
    last_hits_count: {
      id: 'last_hits_count',
      label: 'Last hits',
      percentWidth: 9,
      isSortable: true,
      // The hits of the last run, and among them the ones never seen before
      render: ({ last_hits_count, last_new_hits_count }: Hunts_HuntFragment$data) => {
        if (last_hits_count === null || last_hits_count === undefined) {
          return defaultRender('-');
        }
        return defaultRender(last_hits_count > 0 && last_new_hits_count !== null && last_new_hits_count !== undefined
          ? t_i18n('{hits} ({new} new)', { values: { hits: n(last_hits_count), new: n(last_new_hits_count) } })
          : n(last_hits_count));
      },
    },
    next_run_at: {
      id: 'next_run_at',
      label: 'Next run',
      percentWidth: 8,
      isSortable: true,
      render: ({ next_run_at }: Hunts_HuntFragment$data, { fd }: { fd: (date: string | null | undefined) => string }) => defaultRender(fd(next_run_at)),
    },
    objectLabel: { percentWidth: 7 },
    objectMarking: { percentWidth: 7 },
  };

  const preloadedPaginationProps = {
    linesQuery: huntsListQuery,
    linesFragment: huntsLinesFragment,
    queryRef,
    nodePath: ['hunts', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<HuntsListQuery>;
  const isFiltered = isFilterGroupNotEmpty(viewStorage.filters) || !!viewStorage.searchTerm;
  const matchesNothing = isFiltered && viewStorage.numberOfElements?.original === 0;
  const clearFilters = () => {
    helpers.handleClearAllFilters();
    if (viewStorage.searchTerm) {
      helpers.handleSearch('');
    }
  };

  return (
    <div data-testid="hunts-page">
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <HuntsFirstUse paginationOptions={queryPaginationOptions}>
          <div ref={setStatisticsElement} style={{ marginBottom: 16 }}>
            <HuntStatistics
              showWidgets={showCharts}
              action={(
                <Button
                  variant="tertiary"
                  onClick={toggleCharts}
                  startIcon={<BarChartOutlined fontSize="small" />}
                  aria-pressed={showCharts}
                >
                  {showCharts ? t_i18n('Hide charts') : t_i18n('Show charts')}
                </Button>
              )}
            />
          </div>
          {matchesNothing && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }} data-testid="hunts-no-match">
              <Text variant="content-compact">{t_i18n('No hunt matches these filters')}</Text>
              <Button variant="secondary" size="small" onClick={clearFilters} data-testid="hunts-clear-filters">{t_i18n('Clear filters')}</Button>
            </div>
          )}
          <div ref={setTableElement} style={{ height: tableHeight }}>
            {queryRef && tableElement && (
              <DataTable
                rootRef={tableElement}
                storageKey={LOCAL_STORAGE_KEY}
                initialValues={initialValues}
                preloadedPaginationProps={preloadedPaginationProps}
                resolvePath={(data: Hunts_HuntsFragment$data) => data.hunts?.edges?.map((n) => n?.node)}
                dataColumns={dataColumns}
                lineFragment={huntsLineFragment}
                contextFilters={contextFilters}
                exportContext={{ entity_type: HUNT_ENTITY_TYPE }}
                availableEntityTypes={[HUNT_ENTITY_TYPE]}
                emptyStateMessage={t_i18n('No hunt matches these filters')}
                additionalHeaderButtons={[
                  <Security key="hunt-quick-start" needs={[KNOWLEDGE_KNUPDATE]}>
                    <HuntQuickStartMenu />
                  </Security>,
                  <HuntPackExportButton key="hunt-pack-export" selectionOptions={queryPaginationOptions} />,
                  <Security key="hunt-pack-import" needs={[KNOWLEDGE_KNUPDATE]}>
                    <HuntPackImportButton paginationOptions={queryPaginationOptions} showHubLink={false} />
                  </Security>,
                ]}
                createButton={(
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <HuntCreation paginationOptions={queryPaginationOptions} />
                  </Security>
                )}
              />
            )}
          </div>
        </HuntsFirstUse>
      </Suspense>
    </div>
  );
};

export default Hunts;
