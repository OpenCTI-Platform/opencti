import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link, Navigate, useParams } from 'react-router';
import { Typography } from '@mui/material';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useGranted, { INGESTION, MODULES } from '../../../../utils/hooks/useGranted';
import { ASSERTION_KIND_TO_SOURCE_KIND } from './sourceIntelligenceUtils';
import { SourceRefRedirectQuery } from './__generated__/SourceRefRedirectQuery.graphql';

const sourceRefRedirectQuery = graphql`
  query SourceRefRedirectQuery($filters: FilterGroup) {
    sources(first: 1, filters: $filters) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

interface NoScorecardProps {
  fallback: string | null;
}

// Authors keep their entity page when they have no scorecard (below the minimum volume, or no access to the Sources)
const NoScorecard = ({ fallback }: NoScorecardProps) => {
  const { t_i18n } = useFormatter();
  if (fallback) {
    return <Navigate to={fallback} replace={true} />;
  }
  return (
    <div data-testid="source-ref-no-scorecard">
      <Card title={t_i18n('Source scorecard')}>
        <Typography variant="body2" sx={{ marginBottom: 1 }}>
          {t_i18n('This source has no scorecard yet: connectors and feeds get one at the next computation, authors and analysts above a minimum volume.')}
        </Typography>
        <Link to="/dashboard/integrations/sources">{t_i18n('Back to the sources')}</Link>
      </Card>
    </div>
  );
};

interface SourceRefRedirectComponentProps {
  queryRef: PreloadedQuery<SourceRefRedirectQuery>;
  fallback: string | null;
}

const SourceRefRedirectComponent = ({ queryRef, fallback }: SourceRefRedirectComponentProps) => {
  const { sources } = usePreloadedQuery(sourceRefRedirectQuery, queryRef);
  const sourceId = sources?.edges?.[0]?.node?.id;
  if (!sourceId) {
    return <NoScorecard fallback={fallback} />;
  }
  return <Navigate to={`/dashboard/integrations/sources/source/${sourceId}`} replace={true} />;
};

interface SourceRefLoaderProps {
  sourceKind: string;
  refId: string;
  fallback: string | null;
}

const SourceRefLoader = ({ sourceKind, refId, fallback }: SourceRefLoaderProps) => {
  const queryRef = useQueryLoading<SourceRefRedirectQuery>(sourceRefRedirectQuery, {
    filters: {
      mode: 'and',
      filters: [
        { key: ['source_kind'], values: [sourceKind], operator: 'eq', mode: 'or' },
        { key: ['ref_id'], values: [refId], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  });
  if (!queryRef) {
    return <Loader variant={LoaderVariant.container} />;
  }
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <SourceRefRedirectComponent queryRef={queryRef} fallback={fallback} />
    </Suspense>
  );
};

/**
 * Scorecard of a provenance source identified by its assertion kind and id (the Sources card of an entity only knows
 * these), redirecting to the scorecard page of the matching source.
 */
const SourceRefRedirect = () => {
  const { kind, refId } = useParams() as { kind: string; refId: string };
  const canAccessSources = useGranted([MODULES, INGESTION]);
  const sourceKind = ASSERTION_KIND_TO_SOURCE_KIND[kind];
  const fallback = kind === 'author' ? `/dashboard/id/${encodeURIComponent(refId)}` : null;
  if (!canAccessSources || !sourceKind) {
    return <NoScorecard fallback={fallback} />;
  }
  return <SourceRefLoader sourceKind={sourceKind} refId={refId} fallback={fallback} />;
};

export default SourceRefRedirect;
