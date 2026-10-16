import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Card from '../../../components/common/card/Card';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import { PATH_HUNT, PATH_HUNT_RUN, PATH_HUNTS } from '../common/routes/paths';
import { HuntRunStatusChip, HuntStatusChip, HuntVerdictChip } from './HuntChips';
import { HuntsOfEntityQuery } from './__generated__/HuntsOfEntityQuery.graphql';

// The overview widget lists the latest hunts, the Defense tab all of them up to its limit
type HuntsOfEntityVariant = 'overview' | 'defense';
const HUNTS_OF_ENTITY_LIMIT: Record<HuntsOfEntityVariant, number> = { overview: 10, defense: 100 };

const huntsOfEntityQuery = graphql`
  query HuntsOfEntityQuery($filters: FilterGroup, $first: Int, $entityId: String!) {
    huntEntityActivity(id: $entityId) {
      hunted_at
      matched_at
    }
    hunts(first: $first, filters: $filters, orderBy: last_run_at, orderMode: desc) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          hunt_status
          last_run_at
          last_hits_count
          runs(
            first: 1
            orderBy: created_at
            orderMode: desc
            filters: { mode: and, filters: [{ key: ["hunt_run_mode"], values: ["execute"] }], filterGroups: [] }
          ) {
            edges {
              node {
                id
                verdict
                hunt_run_status
                completed_at
                hits_count
                entity_matched(id: $entityId)
              }
            }
          }
        }
      }
    }
  }
`;

/** The hunts that look for an entity or take it as a source, through their hunt-target and hunt-source refs. */
export const huntsOfEntityFilters = (entityId: string) => ({
  mode: 'or' as const,
  filters: [
    { key: ['huntSources'], values: [entityId] },
    { key: ['huntTargets'], values: [entityId] },
  ],
  filterGroups: [],
});

interface HuntsOfEntityProps {
  entityId: string;
  variant?: HuntsOfEntityVariant;
}

const HuntsOfEntityCard = ({ entityId, variant = 'overview' }: HuntsOfEntityProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, n } = useFormatter();
  const { hunts, huntEntityActivity } = useLazyLoadQuery<HuntsOfEntityQuery>(
    huntsOfEntityQuery,
    { filters: huntsOfEntityFilters(entityId), first: HUNTS_OF_ENTITY_LIMIT[variant], entityId },
    { fetchPolicy: 'store-and-network' },
  );
  const edges = hunts?.edges ?? [];
  const total = hunts?.pageInfo?.globalCount ?? 0;
  // Any hunt that looked the entity up dates it, through its filter or a report as well as when it names it
  const huntedAt = huntEntityActivity?.hunted_at;
  const matchedAt = huntEntityActivity?.matched_at;
  const activity = huntedAt ? (
    <Text variant="content-caption" style={{ display: 'block', marginBottom: theme.spacing(1), color: theme.palette.text.secondary }} data-testid="hunts-of-entity-activity">
      {matchedAt
        ? t_i18n('Last hunted {hunted}, last matched {matched}', { values: { hunted: fldt(huntedAt), matched: fldt(matchedAt) } })
        : t_i18n('Last hunted {hunted}, never matched by a hunt', { values: { hunted: fldt(huntedAt) } })}
    </Text>
  ) : null;
  if (edges.length === 0) {
    if (variant !== 'defense' && !activity) {
      return null;
    }
    return (
      <div data-testid="hunts-of-entity-empty">
        <Card title={t_i18n('Hunts')}>
          {activity}
          {variant === 'defense' && <Text variant="content-caption">{t_i18n('No hunt looks for this entity or takes it as a source yet.')}</Text>}
        </Card>
      </div>
    );
  }
  return (
    <div data-testid="hunts-of-entity">
      <Card title={`${t_i18n('Hunts')} (${n(total)})`}>
        {activity}
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
          {edges.map(({ node }) => {
            // The latest execution the user can read gives the chip, the date and the hits, all of one run; the summary
            // of the hunt only stands in for a run the user cannot read
            const latestRun = node.runs?.edges?.[0]?.node;
            let lastRun: { at: string; hits: number } | null = null;
            let lastRunText = '';
            if (latestRun) {
              lastRun = latestRun.completed_at ? { at: latestRun.completed_at, hits: latestRun.hits_count ?? 0 } : null;
            } else if (node.last_run_at) {
              lastRun = { at: node.last_run_at, hits: node.last_hits_count ?? 0 };
            }
            if (lastRun) {
              const hits = t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: lastRun.hits } });
              if (latestRun?.entity_matched === true) {
                lastRunText = t_i18n('Matched by the last run on {date}, {hits}', { values: { date: fldt(lastRun.at), hits } });
              } else if (latestRun?.entity_matched === false) {
                lastRunText = t_i18n('Not matched by the last run on {date}', { values: { date: fldt(lastRun.at) } });
              } else {
                lastRunText = t_i18n('Last run {date}, {hits}', { values: { date: fldt(lastRun.at), hits } });
              }
            }
            return (
              <li key={node.id} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }} data-testid="hunts-of-entity-row">
                <Link to={PATH_HUNT(node.id)} style={{ flex: '1 1 240px', minWidth: 0 }}>
                  <Text variant="content-compact">{node.name}</Text>
                </Link>
                <HuntStatusChip value={node.hunt_status} />
                {latestRun && (latestRun.hunt_run_status === 'completed'
                  ? <HuntVerdictChip value={latestRun.verdict} />
                  : <HuntRunStatusChip value={latestRun.hunt_run_status} />)}
                {!latestRun && !node.last_run_at && (
                  <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Never run')}</Text>
                )}
                {lastRun && (
                  <Text variant="content-caption" style={{ color: theme.palette.text.secondary }} data-testid="hunts-of-entity-last-run">
                    {latestRun ? <Link to={PATH_HUNT_RUN(node.id, latestRun.id)}>{lastRunText}</Link> : lastRunText}
                  </Text>
                )}
              </li>
            );
          })}
        </ul>
        {total > edges.length && (
          <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1) }}>
            <Link to={PATH_HUNTS}>{t_i18n('{count} more in the hunts list', { values: { count: total - edges.length } })}</Link>
          </Text>
        )}
      </Card>
    </div>
  );
};

/**
 * On the pages of intel a hunt can use, the hunts that use it with the verdict of their latest run: a widget of the
 * overview layout, nothing when no hunt uses the intel, and the Defense tab.
 */
const HuntsOfEntity = ({ entityId, variant = 'overview' }: HuntsOfEntityProps) => {
  const huntHidden = useIsHiddenEntities('Hunt');
  if (huntHidden) {
    return null;
  }
  return (
    <Suspense fallback={null}>
      <HuntsOfEntityCard entityId={entityId} variant={variant} />
    </Suspense>
  );
};

export default HuntsOfEntity;
