import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Switch } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Tag from '@common/tag/Tag';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { ValueScoreBar } from './SourcesLeaderboard';
import { formatRatio } from './sourceIntelligenceUtils';
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

const HUB_STATUS_MESSAGES: Record<string, string> = {
  unreachable: 'XTM Hub is unreachable: only the connectors of the local catalog are recommended.',
  not_registered: 'This platform is not registered on XTM Hub: only the connectors of the local catalog are recommended.',
  error: 'XTM Hub returned an error: only the connectors of the local catalog are recommended.',
};

interface CollectionGapsListProps {
  queryRef: PreloadedQuery<CollectionGapsQuery>;
}

const CollectionGapsList = ({ queryRef }: CollectionGapsListProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const theme = useTheme<Theme>();
  const canDeploy = useGranted([MODULES_MODMANAGE]);
  // Gap and connector pairs deployed from this page, until the next gap computation marks them as deployed
  const [deployedHere, setDeployedHere] = useState<Set<string>>(() => new Set());
  const [commitDeploy, deploying] = useApiMutation<CollectionGapsDeployMutation>(collectionGapDeployMutation);
  const handleDeploy = (gapId: string, slug: string) => commitDeploy({
    variables: { id: gapId, slug },
    onCompleted: (response, errors) => {
      const recommendation = response.collectionGapDeployConnector;
      const failure = !errors?.length && recommendation?.status !== 'applied'
        ? `${t_i18n('The recommendation could not be applied')}${recommendation?.error_message ? `: ${recommendation.error_message}` : ''}`
        : null;
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
                <Tag
                  label={gap.is_gap ? t_i18n('Collection gap') : t_i18n('Covered')}
                  color={gap.is_gap ? theme.palette.warn.main : theme.palette.success.main}
                />
                <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
                  {`${t_i18n('Weight')} ${gap.criterion_weight} - ${t_i18n('Computed')} ${gap.computed_at ? nsdt(gap.computed_at) : '-'}`}
                </Typography>
              </Stack>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>{gap.criterion_label}</Typography>
              <Typography variant="caption" component="div" sx={{ color: theme.palette.text.secondary, marginTop: 0.5 }}>
                {`${gap.matched_relationships} ${t_i18n('matching relationships')}, ${gap.recent_relationships} ${t_i18n('recent')}, ${gap.distinct_sources} ${t_i18n('distinct sources')}`}
              </Typography>
              {gap.covering_sources.length > 0 && (
                <Stack direction="row" gap={0.5} flexWrap="wrap" sx={{ marginTop: 1 }}>
                  {gap.covering_sources.map((covering) => (
                    <Tag
                      key={covering.source_id}
                      label={`${covering.source?.name ?? t_i18n('Restricted')} ${formatRatio(covering.share, 0)}`}
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
              {gap.hub_status && HUB_STATUS_MESSAGES[gap.hub_status] && (
                <Typography variant="caption" component="div" sx={{ color: theme.palette.warn.main, marginBottom: 1 }}>
                  {t_i18n(HUB_STATUS_MESSAGES[gap.hub_status])}
                </Typography>
              )}
              {gap.recommended_connectors.length === 0 ? (
                <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
                  {t_i18n('No integration of the catalog covers this criterion yet.')}
                </Typography>
              ) : (
                <Stack gap={1}>
                  {gap.recommended_connectors.map((connector) => {
                    const deployed = connector.deployed || deployedHere.has(`${gap.id}|${connector.slug}`);
                    const deployable = canDeploy && !deployed && connector.manager_supported && !!connector.contract_image;
                    return (
                      <Stack key={connector.slug} direction="row" gap={2} alignItems="center" justifyContent="space-between">
                        <Box sx={{ minWidth: 0 }}>
                          <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>{connector.title}</Typography>
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
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
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
