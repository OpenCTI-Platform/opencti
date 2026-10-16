import React, { CSSProperties, ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { PATH_HUNT_RUN } from '../../common/routes/paths';
import { HuntRunStatusChip, HuntVerdictChip } from '../HuntChips';
import { HuntRunsWidgetListQuery, HuntRunsWidgetListQuery$variables } from './__generated__/HuntRunsWidgetListQuery.graphql';

export const huntRunsWidgetListQuery = graphql`
  query HuntRunsWidgetListQuery(
    $first: Int
    $orderBy: HuntRunsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    huntRuns(first: $first, orderBy: $orderBy, orderMode: $orderMode, filters: $filters) {
      edges {
        node {
          id
          hunt_id
          hunt_run_status
          hits_count
          verdict
          created_at
          connector_name
          hunt {
            id
            name
          }
          securityPlatform {
            id
            name
          }
        }
      }
    }
  }
`;

const HUNT_RUNS_ORDERINGS = ['created_at', 'updated_at', 'completed_at', 'started_at', 'hits_count', 'verdict', 'hunt_run_status', 'hunt_run_trigger'];

/** The query of a list widget on hunt runs: newest first by default, translation previews left out like in the counts. */
export const buildHuntRunsWidgetVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): HuntRunsWidgetListQuery$variables => {
  const selection = resolvedDataSelection[0];
  const { filters } = computeWidgetFiltersForSelection(selection, config);
  const orderBy = selection.sort_by && HUNT_RUNS_ORDERINGS.includes(selection.sort_by) ? selection.sort_by : 'created_at';
  return {
    first: selection.number ?? 10,
    orderBy: orderBy as HuntRunsWidgetListQuery$variables['orderBy'],
    orderMode: (selection.sort_mode ?? 'desc') as HuntRunsWidgetListQuery$variables['orderMode'],
    filters: {
      mode: 'and',
      filters: [{ key: ['hunt_run_mode'], values: ['preview'], operator: 'not_eq', mode: 'or' }],
      filterGroups: filters ? [filters] : [],
    },
  };
};

type HuntRunsWidgetRun = NonNullable<NonNullable<HuntRunsWidgetListQuery['response']['huntRuns']>['edges'][number]>['node'];

export const HuntRunsWidgetRows = ({ runs }: { runs: readonly HuntRunsWidgetRun[] }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  if (runs.length === 0) {
    return <WidgetNoData />;
  }
  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0, height: '100%', overflowY: 'auto' }} data-testid="hunt-runs-widget-list">
      {runs.map((run) => (
        <li key={run.id} style={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
          <Link
            to={PATH_HUNT_RUN(run.hunt_id, run.id)}
            style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1.5), padding: theme.spacing(1, 0), color: 'inherit', textDecoration: 'none' }}
          >
            <span style={{ minWidth: 150 }}><Text variant="content-compact">{fldt(run.created_at)}</Text></span>
            <HuntRunStatusChip value={run.hunt_run_status} />
            <span style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <Text variant="content-compact">{run.hunt?.name ?? t_i18n('Deleted hunt')}</Text>
              </span>
              <Text variant="content-caption">{run.securityPlatform?.name ?? run.connector_name ?? t_i18n('Unknown')}</Text>
            </span>
            <Text variant="content-compact">{t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: run.hits_count ?? 0 } })}</Text>
            <HuntVerdictChip value={run.verdict} />
          </Link>
        </li>
      ))}
    </ul>
  );
};

const HuntRunsWidgetListComponent = ({ queryRef }: { queryRef: PreloadedQuery<HuntRunsWidgetListQuery> }) => {
  const data = usePreloadedQuery(huntRunsWidgetListQuery, queryRef);
  const runs = (data.huntRuns?.edges ?? []).map((edge) => edge.node);
  return <HuntRunsWidgetRows runs={runs} />;
};

interface HuntRunsWidgetListProps {
  variant?: string;
  height?: CSSProperties['height'];
  config: DashboardConfig;
  refreshRate?: number | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters | null;
  popover?: ReactNode;
  host?: WidgetHost;
}

const HuntRunsWidgetList = ({
  variant,
  height,
  config,
  refreshRate = null,
  dataSelection,
  parameters = {},
  popover,
  host,
}: HuntRunsWidgetListProps) => {
  const { t_i18n } = useFormatter();
  const { renderGuards, isPreviewMode, queryRef } = useDashboardViz<HuntRunsWidgetListQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: huntRunsWidgetListQuery,
    config,
    buildQueryVariables: buildHuntRunsWidgetVariables,
  });
  return (
    <WidgetContainer
      padding="horizontal"
      height={height}
      title={parameters?.title ?? t_i18n('Hunt runs')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent {...renderGuards} queryRef={queryRef} host={host}>
        <HuntRunsWidgetListComponent queryRef={queryRef!} />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default HuntRunsWidgetList;
