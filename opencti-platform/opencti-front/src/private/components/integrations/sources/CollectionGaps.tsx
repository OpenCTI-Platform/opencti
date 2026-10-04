import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, Skeleton, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Alert, Chip, Switch, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Tag from '@common/tag/Tag';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { INGESTION_SETINGESTIONS, MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { ValueScoreBar } from './SourcesLeaderboard';
import { useSourceMetricFormat } from './SourceMetricValue';
import { buildHubCoverageSearchUrl, criterionPriority } from './sourceIntelligenceUtils';
import notifyMutationOutcome from './notifyMutationOutcome';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { CollectionGapsQuery } from './__generated__/CollectionGapsQuery.graphql';
import { CollectionGaps_gaps$key } from './__generated__/CollectionGaps_gaps.graphql';
import { CollectionGapsRefetchQuery } from './__generated__/CollectionGapsRefetchQuery.graphql';
import { CollectionGapsDeployMutation } from './__generated__/CollectionGapsDeployMutation.graphql';

const collectionGapsFragment = graphql`
  fragment CollectionGaps_gaps on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 20 }
    cursor: { type: "ID" }
    onlyGaps: { type: "Boolean" }
    pirId: { type: "ID" }
  )
  @refetchable(queryName: "CollectionGapsRefetchQuery") {
    collectionGaps(
      first: $count
      after: $cursor
      onlyGaps: $onlyGaps
      pirId: $pirId
      orderBy: gap_coverage_score
      orderMode: asc
    ) @connection(key: "Pagination_collectionGaps", filters: ["onlyGaps", "pirId"]) {
      edges {
        node {
          id
          name
          pir_id
          pir {
            id
            name
          }
          criterion_label
          criterion_weight
          coverage_score
          is_gap
          matched_relationships
          recent_relationships
          distinct_sources
          object_types
          sectors
          regions
          hub_status
          computed_at
          covering_sources {
            source_id
            matched_count
            share
            source {
              id
              name
            }
          }
          recommended_connectors {
            slug
            title
            short_description
            origin
            score
            contract_image
            manager_supported
            verified
            deployed
            coverage_inferred
            matched_object_types
            matched_sectors
            matched_regions
          }
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

const collectionGapDeployMutation = graphql`
  mutation CollectionGapsDeployMutation($id: ID!, $slug: String!) {
    collectionGapDeployConnector(id: $id, slug: $slug) {
      id
      status
      error_message
    }
  }
`;

export const collectionGapsQuery = graphql`
  query CollectionGapsQuery($count: Int!, $cursor: ID, $onlyGaps: Boolean, $pirId: ID) {
    ...CollectionGaps_gaps @arguments(count: $count, cursor: $cursor, onlyGaps: $onlyGaps, pirId: $pirId)
  }
`;

const PAGE_SIZE = 20;

const CRITERION_PRIORITY_LABELS: Record<'high' | 'medium' | 'low', string> = {
  high: 'High priority criterion',
  medium: 'Medium priority criterion',
  low: 'Low priority criterion',
};

// Why the ranking does not come from XTM Hub alone, and whether trying again can help
const HUB_STATUS_ALERTS: Record<string, { title: string; description: string; retry: boolean }> = {
  partial: {
    title: 'XTM Hub returned a partial ranking.',
    description: 'Its first matches are combined with the connectors of the local catalog.',
    retry: true,
  },
  unreachable: {
    title: 'XTM Hub could not be reached.',
    description: 'Only the connectors of the local catalog are recommended for now.',
    retry: true,
  },
  not_registered: {
    title: 'This platform is not registered on XTM Hub.',
    description: 'Only the connectors of the local catalog are recommended. Register the platform on XTM Hub to rank the whole catalog.',
    retry: false,
  },
  error: {
    title: 'XTM Hub returned an error.',
    description: 'Only the connectors of the local catalog are recommended for now.',
    retry: true,
  },
};

const sourceIntelligenceRecomputeMutation = graphql`
  mutation CollectionGapsRecomputeMutation {
    sourceIntelligenceRecompute
  }
`;

interface CollectionGapsListProps {
  queryRef: PreloadedQuery<CollectionGapsQuery>;
}

const CollectionGapsList = ({ queryRef }: CollectionGapsListProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const theme = useTheme<Theme>();
  const format = useSourceMetricFormat();
  const canDeploy = useGranted([MODULES_MODMANAGE]);
  const canRecompute = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const { settings } = useAuth();
  const hubUrl = settings.platform_xtmhub_url;
  const [commitRecompute, recomputing] = useApiMutation(sourceIntelligenceRecomputeMutation);
  const handleRetry = () => commitRecompute({
    variables: {},
    onCompleted: (_, errors) => {
      notifyMutationOutcome(errors, { success: t_i18n('The scorecards will be recomputed in the next minutes') });
    },
  });
  // Gap and connector pairs deployed from this page, until the next gap computation marks them as deployed
  const [deployedHere, setDeployedHere] = useState<Set<string>>(() => new Set());
  const [commitDeploy, deploying] = useApiMutation<CollectionGapsDeployMutation>(collectionGapDeployMutation);
  const handleDeploy = (gapId: string, slug: string) => commitDeploy({
    variables: { id: gapId, slug },
    onCompleted: (response, errors) => {
      const recommendation = response.collectionGapDeployConnector;
      let failure: string | null = null;
      if (!errors?.length && recommendation?.status !== 'applied') {
        failure = recommendation?.error_message
          ? t_i18n('The connector could not be deployed: {reason}', { values: { reason: recommendation.error_message } })
          : t_i18n('The connector could not be deployed.');
      }
      if (notifyMutationOutcome(errors, { success: t_i18n('Connector deployed through XTM Composer'), failure })) {
        setDeployedHere((current) => new Set(current).add(`${gapId}|${slug}`));
      }
    },
  });
  const queryData = usePreloadedQuery(collectionGapsQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext } = usePaginationFragment<CollectionGapsRefetchQuery, CollectionGaps_gaps$key>(
    collectionGapsFragment,
    queryData,
  );
  const gaps = (data.collectionGaps?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));
  const weightsByPir = new Map<string, number[]>();
  gaps.forEach((gap) => weightsByPir.set(gap.pir_id, [...(weightsByPir.get(gap.pir_id) ?? []), gap.criterion_weight]));
  if (gaps.length === 0) {
    return (
      <Typography variant="body2" sx={{ color: theme.palette.text.secondary, padding: 2 }} data-testid="collection-gaps-empty">
        {t_i18n('No collection gap: every criterion of your PIRs is covered by recent knowledge from several sources.')}
      </Typography>
    );
  }
  return (
    <Stack gap={1.5} data-testid="collection-gaps-list">
      {gaps.map((gap) => (
        <Card key={gap.id} padding="small" data-testid={`collection-gap-${gap.id}`}>
          <Stack direction="row" gap={2} justifyContent="space-between" alignItems="flex-start">
            <Box sx={{ minWidth: 0, flex: 1 }}>
              <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ marginBottom: 0.5 }}>
                {gap.pir ? (
                  <Link to={`/dashboard/pirs/${gap.pir.id}`}>{gap.pir.name}</Link>
                ) : (
                  <Typography variant="body2">{t_i18n('Restricted PIR')}</Typography>
                )}
                <Chip severity={gap.is_gap ? 'medium' : 'low'} size="sm" label={gap.is_gap ? t_i18n('Collection gap') : t_i18n('Covered')} />
                {(() => {
                  const pirWeights = weightsByPir.get(gap.pir_id) ?? [];
                  const priority = criterionPriority(gap.criterion_weight, pirWeights);
                  return priority ? (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span tabIndex={0}>
                          <Tag label={t_i18n(CRITERION_PRIORITY_LABELS[priority])} size="small" />
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>
                        {t_i18n('Weight {weight} in this PIR, where the criteria weigh from {min} to {max}', {
                          values: { weight: gap.criterion_weight, min: Math.min(...pirWeights), max: Math.max(...pirWeights) },
                        })}
                      </TooltipContent>
                    </Tooltip>
                  ) : null;
                })()}
                {gap.computed_at && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Typography variant="caption" tabIndex={0} sx={{ color: theme.palette.text.secondary }}>
                        {t_i18n('Computed {time}', { values: { time: rd(gap.computed_at) } })}
                      </Typography>
                    </TooltipTrigger>
                    <TooltipContent>{fldt(gap.computed_at)}</TooltipContent>
                  </Tooltip>
                )}
              </Stack>
              <Typography variant="body2" sx={{ fontWeight: 'fontWeightMedium' }}>{gap.criterion_label}</Typography>
              <Typography variant="caption" component="div" sx={{ color: theme.palette.text.secondary, marginTop: 0.5 }}>
                {t_i18n('{matched, plural, one {# matching relationship} other {# matching relationships}}, {recent} in the window, {sources, plural, one {# distinct source} other {# distinct sources}}', {
                  values: { matched: gap.matched_relationships, recent: gap.recent_relationships, sources: gap.distinct_sources },
                })}
              </Typography>
              {gap.covering_sources.length > 0 && (
                <Stack direction="row" gap={0.5} flexWrap="wrap" sx={{ marginTop: 1 }}>
                  {gap.covering_sources.map((covering) => (
                    <Tag
                      key={covering.source_id}
                      label={t_i18n('{source}: {share}', {
                        values: { source: covering.source?.name ?? t_i18n('Restricted source'), share: format.ratio(covering.share, 0) ?? '' },
                      })}
                      size="small"
                    />
                  ))}
                </Stack>
              )}
            </Box>
            <Box sx={{ width: 180, flexShrink: 0 }}>
              <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>{t_i18n('Coverage')}</Typography>
              <ValueScoreBar value={gap.coverage_score} />
            </Box>
          </Stack>
          {gap.is_gap && (
            <Box sx={{ marginTop: 2 }}>
              <Typography variant="subtitle2" sx={{ marginBottom: 1 }}>{t_i18n('Recommended integrations')}</Typography>
              {gap.hub_status && HUB_STATUS_ALERTS[gap.hub_status] && (
                <Box sx={{ marginBottom: 1 }}>
                  <Alert
                    severity="warning"
                    title={t_i18n(HUB_STATUS_ALERTS[gap.hub_status].title)}
                    description={t_i18n(HUB_STATUS_ALERTS[gap.hub_status].description)}
                    action={HUB_STATUS_ALERTS[gap.hub_status].retry && canRecompute ? (
                      <Button variant="secondary" size="small" onClick={handleRetry} disabled={recomputing}>{t_i18n('Retry')}</Button>
                    ) : undefined}
                  />
                </Box>
              )}
              {gap.recommended_connectors.length === 0 ? (
                <Stack direction="row" gap={2} alignItems="center" flexWrap="wrap">
                  <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
                    {t_i18n('No integration of the catalog covers this criterion yet.')}
                  </Typography>
                  {hubUrl ? (
                    <Button
                      variant="secondary"
                      size="small"
                      component="a"
                      href={buildHubCoverageSearchUrl(hubUrl, settings.id, gap)}
                      target="_blank"
                      rel="noopener noreferrer"
                      data-testid="collection-gap-browse-hub"
                    >
                      {t_i18n('Browse the XTM Hub catalog')}
                    </Button>
                  ) : (
                    <Button variant="secondary" size="small" component={Link} to="/dashboard/integrations/available">
                      {t_i18n('Browse the catalog')}
                    </Button>
                  )}
                </Stack>
              ) : (
                <Stack gap={1}>
                  {gap.recommended_connectors.map((connector) => {
                    const deployed = connector.deployed || deployedHere.has(`${gap.id}|${connector.slug}`);
                    const deployable = canDeploy && !deployed && connector.manager_supported && !!connector.contract_image;
                    return (
                      <Stack key={connector.slug} direction="row" gap={2} alignItems="center" justifyContent="space-between">
                        <Box sx={{ minWidth: 0 }}>
                          <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                            <Typography variant="body2" sx={{ fontWeight: 'fontWeightMedium' }}>{connector.title}</Typography>
                            <Tag label={connector.origin === 'hub' ? t_i18n('XTM Hub') : t_i18n('Local catalog')} size="small" />
                            {connector.verified && <Tag label={t_i18n('Verified')} size="small" color={theme.palette.success.main} />}
                            {deployed && <Tag label={t_i18n('Already deployed')} size="small" />}
                          </Stack>
                          <Typography variant="caption" component="div" sx={{ color: theme.palette.text.secondary }}>
                            {[...connector.matched_object_types, ...connector.matched_sectors, ...connector.matched_regions].join(', ')
                              || connector.short_description}
                          </Typography>
                        </Box>
                        {deployable && (
                          <Button
                            variant="secondary"
                            size="small"
                            disabled={deploying}
                            onClick={() => handleDeploy(gap.id, connector.slug)}
                            data-testid={`collection-gap-deploy-${connector.slug}`}
                          >
                            {t_i18n('Deploy')}
                          </Button>
                        )}
                        {!deployable && !deployed && (
                          <Button
                            variant="tertiary"
                            size="small"
                            component={Link}
                            to={`/dashboard/integrations/catalog/${connector.slug}`}
                          >
                            {t_i18n('Open in catalog')}
                          </Button>
                        )}
                      </Stack>
                    );
                  })}
                </Stack>
              )}
            </Box>
          )}
        </Card>
      ))}
      {hasNext && (
        <Stack direction="row" justifyContent="center">
          <Button variant="secondary" onClick={() => loadNext(PAGE_SIZE)} disabled={isLoadingNext}>{t_i18n('Load more')}</Button>
        </Stack>
      )}
    </Stack>
  );
};

const CollectionGapsView = () => {
  const { t_i18n } = useFormatter();
  const [onlyGaps, setOnlyGaps] = useState(true);
  const queryRef = useQueryLoading<CollectionGapsQuery>(collectionGapsQuery, { count: PAGE_SIZE, onlyGaps });
  return (
    <Stack gap={2} data-testid="collection-gaps">
      <Stack direction="row" justifyContent="space-between" alignItems="center" gap={2}>
        <Typography variant="body2">
          {t_i18n('Coverage of every PIR criterion by recent knowledge and distinct sources, with the catalog integrations that would close the gaps.')}
        </Typography>
        <Switch checked={onlyGaps} onCheckedChange={setOnlyGaps} label={t_i18n('Only gaps')} data-testid="collection-gaps-only" />
      </Stack>
      {queryRef && (
        <Suspense fallback={<Skeleton variant="rounded" height={160} aria-hidden />}>
          <CollectionGapsList queryRef={queryRef} />
        </Suspense>
      )}
    </Stack>
  );
};

const CollectionGaps = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  if (!isEnterpriseEdition) {
    return <EnterpriseEdition feature={t_i18n('Collection gaps')} />;
  }
  return <CollectionGapsView />;
};

export default CollectionGaps;
