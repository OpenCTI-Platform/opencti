import { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { ProgressBar } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import type { Theme } from '../../../../components/Theme';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useGranted, { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import CurationFirstUse from './CurationFirstUse';
import CurationSkeleton from './CurationSkeleton';
import KnowledgeHealthScore from './KnowledgeHealthScore';
import useCurationLabels, { CURATION_PROPOSALS_PATH, formatPercent, notifyPayloadErrors, scoreTone } from './curationUtils';
import { KnowledgeHealthQuery } from './__generated__/KnowledgeHealthQuery.graphql';
import { KnowledgeHealthRefreshMutation } from './__generated__/KnowledgeHealthRefreshMutation.graphql';

const knowledgeHealthQuery = graphql`
  query KnowledgeHealthQuery {
    knowledgeHealth {
      id
      snapshot_date
      health_score
      score_trend
      curated_entities_count
      duplicate_estimate
      duplicate_rate
      contradiction_count
      stale_count
      stale_share
      alias_coverage
      source_conflict_rate
      open_proposals_count
      auto_applied_count
      accepted_count
      rejected_count
      reverted_count
      merges_count
      unmerges_count
      digest_sent_at
      score_breakdown {
        component
        value
        weight
        score
      }
    }
    knowledgeHealthSnapshots(first: 90, orderBy: snapshot_date, orderMode: desc) {
      edges {
        node {
          id
          snapshot_date
          health_score
        }
      }
    }
    curationStatistics {
      open_by_kind {
        key
        count
      }
      next_snapshot_date
    }
  }
`;

const knowledgeHealthRefreshMutation = graphql`
  mutation KnowledgeHealthRefreshMutation {
    knowledgeHealthRefresh {
      id
      health_score
      snapshot_date
    }
  }
`;

const RATE_COMPONENTS = ['duplicates', 'contradictions', 'staleness', 'alias_coverage', 'source_conflicts'];

const Counter = ({ label, value }: { label: string; value: string | number }) => {
  const theme = useTheme<Theme>();
  return (
    <div>
      <Typography variant="body2" color={theme.palette.text.light}>{label}</Typography>
      <Typography variant="h3" sx={{ margin: 0 }} data-testid={`knowledge-health-counter-${label}`}>{value}</Typography>
    </div>
  );
};

const KnowledgeHealthComponent = () => {
  const theme = useTheme<Theme>();
  const { t_i18n, n, fldt } = useFormatter();
  const labels = useCurationLabels();
  const isGrantedToSettings = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const [fetchKey, setFetchKey] = useState(0);
  const data = useLazyLoadQuery<KnowledgeHealthQuery>(knowledgeHealthQuery, {}, { fetchPolicy: 'store-and-network', fetchKey });
  const [commitRefresh, refreshing] = useApiMutation<KnowledgeHealthRefreshMutation>(knowledgeHealthRefreshMutation);
  const health = data.knowledgeHealth;

  const refresh = () => {
    commitRefresh({
      variables: {},
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The Knowledge health snapshot has been refreshed'));
        setFetchKey((key) => key + 1);
      },
    });
  };

  const history = [...(data.knowledgeHealthSnapshots?.edges ?? [])]
    .map((edge) => edge.node)
    .reverse()
    .map((node) => ({ x: node.snapshot_date, y: node.health_score }));

  const header = (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, marginBottom: 2 }}>
      <Typography variant="body2" sx={{ flex: 1 }} color={theme.palette.text.light} data-testid="knowledge-health-status">
        {health && (health.digest_sent_at
          ? t_i18n('Snapshot of {date}, weekly digest sent on {digestDate}', { values: { date: fldt(health.snapshot_date), digestDate: fldt(health.digest_sent_at) } })
          : t_i18n('Snapshot of {date}', { values: { date: fldt(health.snapshot_date) } }))}
        {!health && t_i18n('No snapshot yet')}
      </Typography>
      {isGrantedToSettings && (
        <Button onClick={refresh} disabled={refreshing} data-testid="knowledge-health-refresh">
          {t_i18n('Refresh now')}
        </Button>
      )}
    </Box>
  );

  return (
    <div data-testid="knowledge-health-page">
      {header}
      {!health && (
        <Box sx={{ marginBottom: 2 }}>
          <CurationFirstUse
            testId="knowledge-health-first-use"
            title={t_i18n('No Knowledge health snapshot yet')}
            description={t_i18n('The curation manager computes the Knowledge health score once a day from the duplicates, contradictions, stale knowledge, alias coverage and source conflicts of the curated entities.')}
            nextRunDate={data.curationStatistics.next_snapshot_date}
          />
        </Box>
      )}
      {health && (
        <>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 2, marginBottom: 2 }}>
            <Card title={t_i18n('Knowledge health score')}>
              <KnowledgeHealthScore score={health.health_score} />
              <Box sx={{ display: 'flex', justifyContent: 'center', marginTop: 1 }}>
                {health.score_trend !== null && health.score_trend !== undefined ? (
                  <Tag
                    label={t_i18n('{trend} since the previous snapshot', { values: { trend: `${health.score_trend >= 0 ? '+' : ''}${health.score_trend}` } })}
                    color={labels.trendColor(health.score_trend)}
                    labelTextTransform="none"
                  />
                ) : (
                  <Typography variant="body2" color={theme.palette.text.light}>{t_i18n('First snapshot')}</Typography>
                )}
              </Box>
            </Card>
            <Card title={t_i18n('Score breakdown')}>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="knowledge-health-breakdown">
                {health.score_breakdown.map((item) => (
                  <div key={item.component}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2">
                        {labels.healthComponent(item.component)}
                        <span style={{ color: theme.palette.text.light }}>
                          {' - '}
                          {t_i18n('{value}, weight {weight}', {
                            values: {
                              value: RATE_COMPONENTS.includes(item.component) ? formatPercent(item.value, 1) : item.value,
                              weight: formatPercent(item.weight),
                            },
                          })}
                        </span>
                      </Typography>
                      <Typography variant="body2">{t_i18n('{score} / 100', { values: { score: Math.round(item.score) } })}</Typography>
                    </Box>
                    <ProgressBar
                      value={Math.max(0, Math.min(100, item.score))}
                      tone={scoreTone(item.score)}
                      aria-label={labels.healthComponent(item.component)}
                    />
                  </div>
                ))}
              </Box>
            </Card>
          </Box>
          <Card title={t_i18n('Indicators')} sx={{ marginBottom: 2 }}>
            <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(0, 1fr))', gap: 2 }}>
              <Counter label={t_i18n('Curated entities')} value={n(health.curated_entities_count)} />
              <Counter label={t_i18n('Duplicate estimate')} value={`${n(health.duplicate_estimate)} (${formatPercent(health.duplicate_rate, 1)})`} />
              <Counter label={t_i18n('Contradictions')} value={n(health.contradiction_count)} />
              <Counter label={t_i18n('Stale entities')} value={`${n(health.stale_count)} (${formatPercent(health.stale_share, 1)})`} />
              <Counter label={t_i18n('Alias coverage')} value={formatPercent(health.alias_coverage, 1)} />
              <Counter label={t_i18n('Source conflict rate')} value={formatPercent(health.source_conflict_rate, 1)} />
              <Counter label={t_i18n('Open proposals')} value={n(health.open_proposals_count)} />
              <Counter label={t_i18n('Accepted')} value={n(health.accepted_count)} />
              <Counter label={t_i18n('Auto-applied')} value={n(health.auto_applied_count)} />
              <Counter label={t_i18n('Rejected')} value={n(health.rejected_count)} />
              <Counter label={t_i18n('Reverted')} value={n(health.reverted_count)} />
              <Counter label={t_i18n('Merges / unmerges')} value={`${n(health.merges_count)} / ${n(health.unmerges_count)}`} />
            </Box>
          </Card>
        </>
      )}
      <Box sx={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 2 }}>
        <Card title={t_i18n('Score history')}>
          <Box sx={{ height: 260 }}>
            {history.length > 1 ? (
              <WidgetMultiLines series={[{ name: t_i18n('Knowledge health score'), data: history }]} interval="day" />
            ) : (
              <Typography variant="body2" color={theme.palette.text.light}>{t_i18n('The history appears after two snapshots.')}</Typography>
            )}
          </Box>
        </Card>
        <Card title={t_i18n('Open proposals by kind')}>
          {data.curationStatistics.open_by_kind.length === 0 ? (
            <Typography variant="body2" color={theme.palette.text.light}>{t_i18n('No open proposal')}</Typography>
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {data.curationStatistics.open_by_kind.map((entry) => (
                <Box key={entry.key} sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Link to={`${CURATION_PROPOSALS_PATH}`}>{labels.kind(entry.key)}</Link>
                  <span>{n(entry.count)}</span>
                </Box>
              ))}
            </Box>
          )}
        </Card>
      </Box>
    </div>
  );
};

const KnowledgeHealth = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Knowledge health | Curation | Data'));
  return (
    <Suspense fallback={<CurationSkeleton blocks={[40, 280, 160, 280]} />}>
      <KnowledgeHealthComponent />
    </Suspense>
  );
};

export default KnowledgeHealth;
