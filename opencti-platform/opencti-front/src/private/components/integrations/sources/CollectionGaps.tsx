import React, { ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, useLazyLoadQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { connectorManagerStatusQuery } from '@components/data/connectors/ConnectorManagerStatusContext';
import { ConnectorManagerStatusContextQuery } from '@components/data/connectors/__generated__/ConnectorManagerStatusContextQuery.graphql';
import { Link } from 'react-router';
import { Box, Collapse, Skeleton, Stack, Typography } from '@mui/material';
import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
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
import { buildHubCoverageSearchUrl, criterionPriority, oneClickDeployBlocker } from './sourceIntelligenceUtils';
import notifyMutationOutcome from './notifyMutationOutcome';
import ConnectorDeployDialog, { type ConnectorRequiredSetting, type ConnectorSettingValue, hasOnlyCollectableSettings } from './ConnectorDeployDialog';
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
            pir_criteria {
              weight
            }
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
            required_settings {
              key
              label
              description
              type
              secret
            }
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
  mutation CollectionGapsDeployMutation($id: ID!, $slug: String!, $configuration: [ContractConfigInput!]) {
    collectionGapDeployConnector(id: $id, slug: $slug, configuration: $configuration) {
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

const DeployFailure = ({ cause, onRetry, retrying }: { cause: string | null; onRetry?: () => void; retrying: boolean }) => {
  const { t_i18n } = useFormatter();
  const [detailsOpen, setDetailsOpen] = useState(false);
  return (
    <Box>
      <Alert
        severity="error"
        title={t_i18n('The recommendation could not be applied')}
        description={t_i18n('Nothing was changed. Retry, or read the details to fix the cause first.')}
        action={onRetry ? (
          <Button variant="secondary" size="small" onClick={onRetry} disabled={retrying}>{t_i18n('Retry')}</Button>
        ) : undefined}
      />
      {cause && (
        <>
          <Button
            variant="tertiary"
            size="small"
            onClick={() => setDetailsOpen(!detailsOpen)}
            startIcon={detailsOpen ? <ExpandLessOutlined /> : <ExpandMoreOutlined />}
            aria-expanded={detailsOpen}
          >
            {detailsOpen ? t_i18n('Hide details') : t_i18n('Show details')}
          </Button>
          <Collapse in={detailsOpen}>
            <Typography variant="caption" component="pre" sx={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'monospace' }}>
              {cause}
            </Typography>
          </Collapse>
        </>
      )}
    </Box>
  );
};

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
  // Null when the user cannot read the connector managers
  hasRegisteredManager: boolean | null;
}

interface DeployTarget {
  gapId: string;
  slug: string;
  title: string;
  settings: readonly ConnectorRequiredSetting[];
}

// Reading the connector managers needs the capability to access connectors: only users who can deploy read them
const WithRegisteredManagers = ({ children }: { children: (registered: boolean) => ReactNode }) => {
  const data = useLazyLoadQuery<ConnectorManagerStatusContextQuery>(connectorManagerStatusQuery, {}, { fetchPolicy: 'store-or-network' });
  return <>{children((data.connectorManagers ?? []).length > 0)}</>;
};

const CollectionGapsList = ({ queryRef, hasRegisteredManager }: CollectionGapsListProps) => {
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
  // Failed deployments from this page with their cause, shown under the integration until a retry succeeds
  const [failedHere, setFailedHere] = useState<Map<string, string | null>>(() => new Map());
  const [commitDeploy, deploying] = useApiMutation<CollectionGapsDeployMutation>(collectionGapDeployMutation);
  // Connector whose deployment dialog is open: it says what the connector needs before anything is deployed
  const [deployTarget, setDeployTarget] = useState<DeployTarget | null>(null);
  const handleDeploy = (gapId: string, slug: string, configuration: ConnectorSettingValue[]) => commitDeploy({
    variables: { id: gapId, slug, configuration },
    onCompleted: (response, errors) => {
      setDeployTarget(null);
      const key = `${gapId}|${slug}`;
      const recommendation = response.collectionGapDeployConnector;
      const failed = !errors?.length && recommendation?.status !== 'applied';
      // The cause is shown under the integration, behind Show details
      const failure = failed ? t_i18n('The connector could not be deployed.') : null;
      if (notifyMutationOutcome(errors, { success: t_i18n('Connector deployed through XTM Composer'), failure })) {
        setDeployedHere((current) => new Set(current).add(key));
      }
      setFailedHere((current) => {
        const next = new Map(current);
        if (failed) next.set(key, recommendation?.error_message ?? null);
        else next.delete(key);
        return next;
      });
    },
  });
  const queryData = usePreloadedQuery(collectionGapsQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext } = usePaginationFragment<CollectionGapsRefetchQuery, CollectionGaps_gaps$key>(
    collectionGapsFragment,
    queryData,
  );
  const gaps = (data.collectionGaps?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));
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
                  // Ranked against every criterion of the PIR, whatever the page and the filters show
                  const pirWeights = (gap.pir?.pir_criteria ?? []).map((criterion) => criterion.weight);
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
                    const deployKey = `${gap.id}|${connector.slug}`;
                    const deployed = connector.deployed || deployedHere.has(deployKey);
                    const blocker = oneClickDeployBlocker({
                      inLocalCatalog: !!connector.contract_image,
                      managerSupported: connector.manager_supported,
                      canDeploy,
                      hasRegisteredManager,
                      settingsCollectable: hasOnlyCollectableSettings(connector.required_settings),
                    });
                    const deployable = !deployed && blocker === null;
                    const openDeployDialog = () => setDeployTarget({ gapId: gap.id, slug: connector.slug, title: connector.title, settings: connector.required_settings });
                    return (
                      <Stack key={connector.slug} gap={1}>
                        <Stack direction="row" gap={2} alignItems="center" justifyContent="space-between">
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
                            {!deployed && blocker && (
                              <Typography variant="caption" component="div" sx={{ color: theme.palette.text.secondary }} data-testid={`collection-gap-deploy-blocker-${connector.slug}`}>
                                {t_i18n(blocker)}
                              </Typography>
                            )}
                          </Box>
                          {deployable && (
                            <Button
                              variant="secondary"
                              size="small"
                              disabled={deploying}
                              onClick={openDeployDialog}
                              data-testid={`collection-gap-deploy-${connector.slug}`}
                            >
                              {t_i18n('Deploy {name}', { values: { name: connector.title } })}
                            </Button>
                          )}
                          {!deployable && !deployed && (!connector.contract_image && hubUrl ? (
                            <Button
                              variant="tertiary"
                              size="small"
                              component="a"
                              href={buildHubCoverageSearchUrl(hubUrl, settings.id, gap)}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {t_i18n('Open in XTM Hub')}
                            </Button>
                          ) : (
                            <Button
                              variant="tertiary"
                              size="small"
                              component={Link}
                              to={`/dashboard/integrations/catalog/${connector.slug}`}
                            >
                              {t_i18n('Open in catalog')}
                            </Button>
                          ))}
                        </Stack>
                        {failedHere.has(deployKey) && (
                          <DeployFailure
                            cause={failedHere.get(deployKey) ?? null}
                            onRetry={deployable ? openDeployDialog : undefined}
                            retrying={deploying}
                          />
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
      {deployTarget && (
        <ConnectorDeployDialog
          open
          connectorName={deployTarget.title}
          settings={deployTarget.settings}
          deploying={deploying}
          onClose={() => setDeployTarget(null)}
          onDeploy={(configuration) => handleDeploy(deployTarget.gapId, deployTarget.slug, configuration)}
        />
      )}
    </Stack>
  );
};

const CollectionGapsView = () => {
  const { t_i18n } = useFormatter();
  const canDeploy = useGranted([MODULES_MODMANAGE]);
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
          {canDeploy ? (
            <WithRegisteredManagers>
              {(registered) => <CollectionGapsList queryRef={queryRef} hasRegisteredManager={registered} />}
            </WithRegisteredManagers>
          ) : (
            <CollectionGapsList queryRef={queryRef} hasRegisteredManager={null} />
          )}
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
