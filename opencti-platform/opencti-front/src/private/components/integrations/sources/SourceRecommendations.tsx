import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import Button from '@common/button/Button';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import type { Theme } from '../../../../components/Theme';
import SourceRecommendationCard from './SourceRecommendationCard';
import { RECOMMENDATION_KIND_LABELS, RECOMMENDATION_STATUS_LABELS } from './sourceIntelligenceUtils';
import {
  SourceRecommendationKind,
  SourceRecommendationsQuery,
  SourceRecommendationsQuery$variables,
  SourceRecommendationStatus,
} from './__generated__/SourceRecommendationsQuery.graphql';
import { SourceRecommendations_recommendations$key } from './__generated__/SourceRecommendations_recommendations.graphql';
import { SourceRecommendationsRefetchQuery } from './__generated__/SourceRecommendationsRefetchQuery.graphql';

const recommendationsFragment = graphql`
  fragment SourceRecommendations_recommendations on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    status: { type: "[SourceRecommendationStatus!]" }
    kind: { type: "[SourceRecommendationKind!]" }
    sourceId: { type: "ID" }
  )
  @refetchable(queryName: "SourceRecommendationsRefetchQuery") {
    sourceRecommendations(
      first: $count
      after: $cursor
      status: $status
      kind: $kind
      sourceId: $sourceId
      orderBy: proposed_at
      orderMode: desc
    ) @connection(key: "Pagination_sourceRecommendations", filters: ["status", "kind", "sourceId"]) {
      edges {
        node {
          id
          ...SourceRecommendationCard_recommendation
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

export const sourceRecommendationsQuery = graphql`
  query SourceRecommendationsQuery(
    $count: Int!
    $cursor: ID
    $status: [SourceRecommendationStatus!]
    $kind: [SourceRecommendationKind!]
    $sourceId: ID
  ) {
    ...SourceRecommendations_recommendations
    @arguments(count: $count, cursor: $cursor, status: $status, kind: $kind, sourceId: $sourceId)
  }
`;

const PAGE_SIZE = 25;
const ALL = 'all';
const STATUS_FILTERS: Array<SourceRecommendationStatus | typeof ALL> = ['proposed', 'applying', 'applied', 'reverting', 'failed', 'reverted', 'dismissed', ALL];
const KIND_FILTERS = [ALL, ...Object.keys(RECOMMENDATION_KIND_LABELS)];

interface SourceRecommendationsListProps {
  queryRef: PreloadedQuery<SourceRecommendationsQuery>;
  hideSource?: boolean;
  emptyMessage: string;
}

export const SourceRecommendationsList = ({ queryRef, hideSource = false, emptyMessage }: SourceRecommendationsListProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const queryData = usePreloadedQuery(sourceRecommendationsQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext, refetch } = usePaginationFragment<SourceRecommendationsRefetchQuery, SourceRecommendations_recommendations$key>(
    recommendationsFragment,
    queryData,
  );
  const edges = data.sourceRecommendations?.edges ?? [];
  // An applied, dismissed or reverted recommendation leaves the current status filter: reload the page
  const handleChange = () => refetch({}, { fetchPolicy: 'network-only' });

  if (edges.length === 0) {
    return (
      <Typography variant="body2" sx={{ color: theme.palette.text.secondary, padding: 2 }} data-testid="source-recommendations-empty">
        {emptyMessage}
      </Typography>
    );
  }
  return (
    <Stack gap={1.5} data-testid="source-recommendations-list">
      <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
        {t_i18n('{count, plural, one {# recommendation} other {# recommendations}}', { values: { count: data.sourceRecommendations?.pageInfo.globalCount ?? edges.length } })}
      </Typography>
      {edges.map((edge) => edge?.node && (
        <SourceRecommendationCard key={edge.node.id} data={edge.node} hideSource={hideSource} onChange={handleChange} />
      ))}
      {hasNext && (
        <Stack direction="row" justifyContent="center">
          <Button variant="secondary" onClick={() => loadNext(PAGE_SIZE)} disabled={isLoadingNext}>
            {t_i18n('Load more')}
          </Button>
        </Stack>
      )}
    </Stack>
  );
};

const SourceRecommendationsInbox = () => {
  const { t_i18n } = useFormatter();
  const [status, setStatus] = useState<SourceRecommendationStatus | typeof ALL>('proposed');
  const [kind, setKind] = useState<string>(ALL);
  const variables: SourceRecommendationsQuery$variables = {
    count: PAGE_SIZE,
    status: status === ALL ? null : [status],
    kind: kind === ALL ? null : [kind as SourceRecommendationKind],
  };
  const queryRef = useQueryLoading<SourceRecommendationsQuery>(sourceRecommendationsQuery, variables);
  return (
    <Stack gap={2} data-testid="source-recommendations-inbox">
      <Stack direction="row" gap={2} alignItems="flex-end" flexWrap="wrap">
        <Select value={status} onValueChange={(next) => setStatus(next as SourceRecommendationStatus | typeof ALL)}>
          <SelectTrigger aria-label={t_i18n('Status')} data-testid="source-recommendations-status">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Status')}>
            {STATUS_FILTERS.map((value) => (
              <SelectItem key={value} value={value}>
                {value === ALL ? t_i18n('All statuses') : t_i18n(RECOMMENDATION_STATUS_LABELS[value])}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={kind} onValueChange={setKind}>
          <SelectTrigger aria-label={t_i18n('Kind')} data-testid="source-recommendations-kind">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Kind')}>
            {KIND_FILTERS.map((value) => (
              <SelectItem key={value} value={value}>
                {value === ALL ? t_i18n('All kinds') : t_i18n(RECOMMENDATION_KIND_LABELS[value])}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Stack>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <SourceRecommendationsList
            queryRef={queryRef}
            emptyMessage={t_i18n('No recommendation matches these filters. Recommendations are produced after each nightly computation.')}
          />
        </Suspense>
      )}
    </Stack>
  );
};

const SourceRecommendations = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  if (!isEnterpriseEdition) {
    return <EnterpriseEdition feature={t_i18n('Source Intelligence recommendations')} />;
  }
  return <SourceRecommendationsInbox />;
};

export default SourceRecommendations;
