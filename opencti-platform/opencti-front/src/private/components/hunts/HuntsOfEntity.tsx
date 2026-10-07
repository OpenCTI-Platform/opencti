import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Card from '../../../components/common/card/Card';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import { PATH_HUNT, PATH_HUNTS } from '../common/routes/paths';
import { HuntRunStatusChip, HuntStatusChip, HuntVerdictChip } from './HuntChips';
import { HuntsOfEntityQuery } from './__generated__/HuntsOfEntityQuery.graphql';

const HUNTS_OF_ENTITY_LIMIT = 10;

const huntsOfEntityQuery = graphql`
  query HuntsOfEntityQuery($filters: FilterGroup, $first: Int) {
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

const HuntsOfEntityCard = ({ entityId }: { entityId: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, n } = useFormatter();
  const { hunts } = useLazyLoadQuery<HuntsOfEntityQuery>(
    huntsOfEntityQuery,
    { filters: huntsOfEntityFilters(entityId), first: HUNTS_OF_ENTITY_LIMIT },
    { fetchPolicy: 'store-and-network' },
  );
  const edges = hunts?.edges ?? [];
  const total = hunts?.pageInfo?.globalCount ?? 0;
  if (edges.length === 0) {
    return null;
  }
  return (
    <div style={{ marginBottom: theme.spacing(2.5) }} data-testid="hunts-of-entity">
      <Card title={`${t_i18n('Hunts')} (${n(total)})`}>
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
          {edges.map(({ node }) => {
            // The latest execution the user can read gives the chip, the date and the hits, all of one run; the summary
            // of the hunt only stands in for a run the user cannot read
            const latestRun = node.runs?.edges?.[0]?.node;
            let lastRun: { at: string; hits: number } | null = null;
            if (latestRun) {
              lastRun = latestRun.completed_at ? { at: latestRun.completed_at, hits: latestRun.hits_count ?? 0 } : null;
            } else if (node.last_run_at) {
              lastRun = { at: node.last_run_at, hits: node.last_hits_count ?? 0 };
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
                  <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
                    {t_i18n('Last run {date}, {hits}', {
                      values: {
                        date: fldt(lastRun.at),
                        hits: t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: lastRun.hits } }),
                      },
                    })}
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

/** On the pages of intel a hunt can use, the hunts that use it with the verdict of their latest run; nothing when none does. */
const HuntsOfEntity = ({ entityId }: { entityId: string }) => {
  const huntHidden = useIsHiddenEntities('Hunt');
  if (huntHidden) {
    return null;
  }
  return (
    <Suspense fallback={null}>
      <HuntsOfEntityCard entityId={entityId} />
    </Suspense>
  );
};

export default HuntsOfEntity;
