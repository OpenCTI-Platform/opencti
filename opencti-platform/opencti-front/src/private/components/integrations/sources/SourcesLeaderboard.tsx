import React from 'react';
import { graphql } from 'react-relay';
import { Box, Stack } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { CableOutlined, PersonOutlined, RssFeedOutlined, TravelExploreOutlined } from '@mui/icons-material';
import Tag from '@common/tag/Tag';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import type { Theme } from '../../../../components/Theme';
import { COST_PERIOD_LABELS, formatCost, formatCount, formatHours, formatRatio, formatScore, scoreLevel, SOURCE_KIND_LABELS } from './sourceIntelligenceUtils';
import { SourcesLeaderboardLinesQuery, SourcesLeaderboardLinesQuery$variables } from './__generated__/SourcesLeaderboardLinesQuery.graphql';
import { SourcesLeaderboard_sources$data } from './__generated__/SourcesLeaderboard_sources.graphql';
import { SourcesLeaderboard_source$data } from './__generated__/SourcesLeaderboard_source.graphql';

const sourceLineFragment = graphql`
  fragment SourcesLeaderboard_source on Source {
    id
    entity_type
    name
    source_kind
    enabled
    quarantined
    tags
    last_computed_at
    latest_value_score
    latest_volume
    latest_unique_contribution
    latest_corroboration_rate
    latest_lead_time_hours
    latest_accuracy
    latest_relevance
    latest_impact_score
    latest_noise
    latest_freshness_hours
    latest_cost_per_actionable
    latest_community_uniqueness
    cost {
      amount
      currency
      period
    }
  }
`;

const sourcesLinesFragment = graphql`
  fragment SourcesLeaderboard_sources on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "SourcesOrdering", defaultValue: latest_value_score }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SourcesLeaderboardRefetchQuery") {
    sources(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_sources") {
      edges {
        node {
          id
          ...SourcesLeaderboard_source
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

export const sourcesLeaderboardLinesQuery = graphql`
  query SourcesLeaderboardLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: SourcesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SourcesLeaderboard_sources
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

const LOCAL_STORAGE_KEY = 'sourceIntelligenceLeaderboard';
const AVAILABLE_FILTER_KEYS = ['source_kind', 'enabled', 'quarantined', 'tags', 'latest_value_score', 'latest_accuracy', 'latest_noise', 'latest_unique_contribution'];

const SOURCE_KIND_ICONS: Record<string, React.ReactElement> = {
  connector: <CableOutlined fontSize="small" color="primary" />,
  ingestion_feed: <RssFeedOutlined fontSize="small" color="primary" />,
  author: <TravelExploreOutlined fontSize="small" color="primary" />,
  manual: <PersonOutlined fontSize="small" color="primary" />,
};

export const SourceKindIcon = ({ kind }: { kind: string }) => SOURCE_KIND_ICONS[kind] ?? SOURCE_KIND_ICONS.manual;

export const ValueScoreBar = ({ value }: { value: number | null | undefined }) => {
  const theme = useTheme<Theme>();
  const level = scoreLevel(value, { scale: 100 });
  const colors = {
    good: theme.palette.success.main,
    average: theme.palette.warn.main,
    poor: theme.palette.error.main,
    unknown: theme.palette.text.disabled,
  };
  const width = typeof value === 'number' ? Math.max(4, Math.min(100, value)) : 0;
  return (
    <Stack direction="row" alignItems="center" gap={1} sx={{ width: '100%' }}>
      <Box sx={{ width: 28, fontWeight: 600 }}>{formatScore(value)}</Box>
      <Box sx={{ flex: 1, height: 6, borderRadius: 3, backgroundColor: theme.palette.background.accent, overflow: 'hidden' }}>
        <Box sx={{ width: `${width}%`, height: '100%', backgroundColor: colors[level] }} />
      </Box>
    </Stack>
  );
};

const SourcesLeaderboard = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  const initialValues = {
    searchTerm: '',
    sortBy: 'latest_value_score',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<SourcesLeaderboardLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('Source', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as SourcesLeaderboardLinesQuery$variables;
  const queryRef = useQueryLoading<SourcesLeaderboardLinesQuery>(sourcesLeaderboardLinesQuery, queryPaginationOptions);

  const ratioCell = (value: number | null | undefined) => formatRatio(value);
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: 'Name',
      percentWidth: 16,
      isSortable: true,
      render: ({ name, enabled, quarantined }: SourcesLeaderboard_source$data) => (
        <Stack direction="row" alignItems="center" gap={1} sx={{ overflow: 'hidden' }}>
          <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</Box>
          {quarantined && <Tag label={t_i18n('Quarantined')} size="small" />}
          {!enabled && <Tag label={t_i18n('Disabled')} size="small" />}
        </Stack>
      ),
    },
    source_kind: {
      id: 'source_kind',
      label: 'Kind',
      percentWidth: 8,
      isSortable: true,
      render: ({ source_kind }: SourcesLeaderboard_source$data) => t_i18n(SOURCE_KIND_LABELS[source_kind] ?? source_kind),
    },
    latest_value_score: {
      id: 'latest_value_score',
      label: 'Value',
      percentWidth: 9,
      isSortable: true,
      render: ({ latest_value_score }: SourcesLeaderboard_source$data) => <ValueScoreBar value={latest_value_score} />,
    },
    latest_volume: {
      id: 'latest_volume',
      label: 'Volume',
      percentWidth: 6,
      isSortable: true,
      render: ({ latest_volume }: SourcesLeaderboard_source$data) => formatCount(latest_volume),
    },
    latest_unique_contribution: {
      id: 'latest_unique_contribution',
      label: 'Unique',
      percentWidth: 7,
      isSortable: true,
      render: ({ latest_unique_contribution }: SourcesLeaderboard_source$data) => ratioCell(latest_unique_contribution),
    },
    latest_corroboration_rate: {
      id: 'latest_corroboration_rate',
      label: 'Corroborated',
      percentWidth: 7,
      isSortable: true,
      render: ({ latest_corroboration_rate }: SourcesLeaderboard_source$data) => ratioCell(latest_corroboration_rate),
    },
    latest_lead_time_hours: {
      id: 'latest_lead_time_hours',
      label: 'Lead time',
      percentWidth: 7,
      isSortable: true,
      render: ({ latest_lead_time_hours }: SourcesLeaderboard_source$data) => formatHours(latest_lead_time_hours),
    },
    latest_accuracy: {
      id: 'latest_accuracy',
      label: 'Accuracy',
      percentWidth: 7,
      isSortable: true,
      render: ({ latest_accuracy }: SourcesLeaderboard_source$data) => ratioCell(latest_accuracy),
    },
    latest_relevance: {
      id: 'latest_relevance',
      label: 'Relevance',
      percentWidth: 6,
      isSortable: isEnterpriseEdition,
      render: ({ latest_relevance }: SourcesLeaderboard_source$data) => (isEnterpriseEdition ? ratioCell(latest_relevance) : '-'),
    },
    latest_impact_score: {
      id: 'latest_impact_score',
      label: 'Impact',
      percentWidth: 6,
      isSortable: true,
      render: ({ latest_impact_score }: SourcesLeaderboard_source$data) => formatScore(latest_impact_score),
    },
    latest_noise: {
      id: 'latest_noise',
      label: 'Noise',
      percentWidth: 6,
      isSortable: true,
      render: ({ latest_noise }: SourcesLeaderboard_source$data) => ratioCell(latest_noise),
    },
    latest_freshness_hours: {
      id: 'latest_freshness_hours',
      label: 'Last seen',
      percentWidth: 7,
      isSortable: true,
      render: ({ latest_freshness_hours }: SourcesLeaderboard_source$data) => formatHours(latest_freshness_hours),
    },
    latest_cost_per_actionable: {
      id: 'latest_cost_per_actionable',
      label: 'Cost / actionable',
      percentWidth: 8,
      isSortable: true,
      render: ({ latest_cost_per_actionable, cost }: SourcesLeaderboard_source$data) => (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{formatCost(latest_cost_per_actionable, cost?.currency)}</span>
          </TooltipTrigger>
          <TooltipContent>
            {cost ? `${cost.amount} ${cost.currency} - ${t_i18n(COST_PERIOD_LABELS[cost.period] ?? cost.period)}` : t_i18n('No cost declared')}
          </TooltipContent>
        </Tooltip>
      ),
    },
  };

  return (
    <div data-testid="source-intelligence-leaderboard">
      {queryRef && (
        <DataTable
          removeSelectAll
          disableLineSelection
          disableToolBar
          dataColumns={dataColumns}
          resolvePath={(data: SourcesLeaderboard_sources$data) => data.sources?.edges?.map((edge) => edge?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          availableFilterKeys={AVAILABLE_FILTER_KEYS}
          preloadedPaginationProps={{
            linesQuery: sourcesLeaderboardLinesQuery,
            linesFragment: sourcesLinesFragment,
            queryRef,
            nodePath: ['sources', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={sourceLineFragment}
          entityTypes={['Source']}
          searchContextFinal={{ entityTypes: ['Source'] }}
          icon={(source: SourcesLeaderboard_source$data) => <SourceKindIcon kind={source.source_kind} />}
          getComputeLink={(source: SourcesLeaderboard_source$data) => `/dashboard/integrations/sources/source/${source.id}`}
          emptyStateMessage={t_i18n('No source has been scored yet. Sources are discovered and scored by the source intelligence manager.')}
        />
      )}
    </div>
  );
};

export default SourcesLeaderboard;
