import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link, useNavigate, useParams } from 'react-router';
import { Chip, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { INVESTIGATION_INUPDATE, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { resolveLink } from '../../../../utils/Entity';
import GraphSimilarityEvidence from '../../common/graph_analytics/GraphSimilarityEvidence';
import { GRAPH_CLUSTER_KIND_LABELS, GRAPH_CLUSTER_SOURCE_LABELS, GRAPH_CLUSTERS_PATH, reportPayloadErrors } from '../../common/graph_analytics/graphAnalyticsUtils';
import GraphClusterPromoteDialog from './GraphClusterPromoteDialog';
import GraphClusterMembers from './GraphClusterMembers';
import type { RootGraphClusterQuery } from './__generated__/RootGraphClusterQuery.graphql';
import type { RootGraphClusterInvestigationMutation } from './__generated__/RootGraphClusterInvestigationMutation.graphql';

const graphClusterQuery = graphql`
  query RootGraphClusterQuery($id: String!) {
    graphCluster(id: $id) {
      id
      name
      cluster_kind
      cluster_source
      members_count
      promotion_max_members
      last_computed_at
      created_at
      representatives {
        id
        entity_type
        representative {
          main
        }
      }
      features {
        family
        count
        entities {
          id
          entity_type
          representative {
            main
          }
        }
      }
      promotedTo {
        id
        entity_type
        representative {
          main
        }
      }
      timeline(interval: "month") {
        date
        value
      }
    }
  }
`;

const addToInvestigationMutation = graphql`
  mutation RootGraphClusterInvestigationMutation($id: ID!) {
    graphClusterAddToInvestigation(id: $id) {
      id
    }
  }
`;

type PromotionTarget = 'Grouping' | 'Campaign';

const GraphClusterComponent = ({ queryRef }: { queryRef: PreloadedQuery<RootGraphClusterQuery> }) => {
  const { t_i18n, fldt, n } = useFormatter();
  const navigate = useNavigate();
  const { setTitle } = useConnectedDocumentModifier();
  const canPromote = useGranted([KNOWLEDGE_KNUPDATE]);
  const canInvestigate = useGranted([INVESTIGATION_INUPDATE]);
  const [promotion, setPromotion] = useState<PromotionTarget | null>(null);
  const [commitInvestigation, investigating] = useApiMutation<RootGraphClusterInvestigationMutation>(addToInvestigationMutation);
  const { graphCluster: cluster } = usePreloadedQuery(graphClusterQuery, queryRef);
  if (!cluster) return <ErrorNotFound />;
  setTitle(`${cluster.name} | ${t_i18n('Graph clusters')}`);
  const tooLargeToPromote = cluster.members_count > cluster.promotion_max_members;

  const addToInvestigation = () => {
    commitInvestigation({
      variables: { id: cluster.id },
      onCompleted: (response, errors) => {
        if (reportPayloadErrors(errors) || !response.graphClusterAddToInvestigation?.id) return;
        navigate(`/dashboard/workspaces/investigations/${response.graphClusterAddToInvestigation.id}`);
      },
    });
  };

  return (
    <div data-testid="graph-cluster-page">
      <Breadcrumbs elements={[
        { label: t_i18n('Analyses') },
        { label: t_i18n('Graph clusters'), link: GRAPH_CLUSTERS_PATH },
        { label: cluster.name, current: true },
      ]}
      />
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3, flexWrap: 'wrap' }}>
        <Text variant="title-xl" as="h1">{cluster.name}</Text>
        <Chip label={t_i18n(GRAPH_CLUSTER_KIND_LABELS[cluster.cluster_kind] ?? cluster.cluster_kind)} severity="info" />
        <Chip label={t_i18n(GRAPH_CLUSTER_SOURCE_LABELS[cluster.cluster_source] ?? cluster.cluster_source)} />
        <Box sx={{ flex: 1 }} />
        {canInvestigate && (
          <Button variant="secondary" onClick={addToInvestigation} disabled={investigating || tooLargeToPromote}>
            {t_i18n('Add to investigation')}
          </Button>
        )}
        {canPromote && (
          <>
            <Button variant="secondary" onClick={() => setPromotion('Campaign')} disabled={tooLargeToPromote} data-testid="graph-cluster-create-campaign">
              {t_i18n('Create Campaign')}
            </Button>
            <Button onClick={() => setPromotion('Grouping')} disabled={tooLargeToPromote} data-testid="graph-cluster-create-grouping">
              {t_i18n('Create Grouping')}
            </Button>
          </>
        )}
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 3, mb: 3 }}>
        <Card title={t_i18n('Details')}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            <Text variant="content-compact">{`${t_i18n('Members you can access')}: ${n(cluster.members_count)}`}</Text>
            {canPromote && tooLargeToPromote && (
              <Text variant="content-compact">
                {`${t_i18n('Too many members to create a Grouping or a Campaign, maximum')}: ${n(cluster.promotion_max_members)}`}
              </Text>
            )}
            {canInvestigate && tooLargeToPromote && (
              <Text variant="content-compact">
                {`${t_i18n('Too many members to add them to an investigation, maximum')}: ${n(cluster.promotion_max_members)}`}
              </Text>
            )}
            <Text variant="content-compact">{`${t_i18n('Last computation')}: ${fldt(cluster.last_computed_at)}`}</Text>
            <Text variant="content-compact">{`${t_i18n('First detected')}: ${fldt(cluster.created_at)}`}</Text>
            <Text variant="content-compact">{t_i18n('Clusters are computed from the knowledge graph and never create relationships. Creating a Grouping or a Campaign is an explicit action.')}</Text>
            {cluster.promotedTo.length > 0 && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                <Text variant="content-compact">{`${t_i18n('Promoted to')}:`}</Text>
                {cluster.promotedTo.map((promoted) => (
                  <Link key={promoted.id} to={`${resolveLink(promoted.entity_type)}/${promoted.id}`}>
                    <Chip label={promoted.representative.main} startIcon={<ItemIcon type={promoted.entity_type} size="small" />} />
                  </Link>
                ))}
              </Box>
            )}
          </Box>
        </Card>
        <Card title={t_i18n('Members over time')}>
          <Box sx={{ height: 220 }}>
            {cluster.timeline.length > 0 ? (
              <WidgetMultiAreas
                series={[{
                  name: t_i18n('Members'),
                  data: cluster.timeline.map((entry) => ({ x: new Date(entry.date), y: entry.value })),
                }]}
                interval="month"
              />
            ) : <WidgetNoData />}
          </Box>
        </Card>
        <Card title={t_i18n('Shared features')}>
          <GraphSimilarityEvidence evidence={cluster.features} maxPerFamily={12} />
        </Card>
        <Card title={t_i18n('Representative entities')}>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {cluster.representatives.map((entity) => (
              <Link key={entity.id} to={`${resolveLink(entity.entity_type)}/${entity.id}`}>
                <Chip label={entity.representative.main} startIcon={<ItemIcon type={entity.entity_type} size="small" />} />
              </Link>
            ))}
          </Box>
        </Card>
      </Box>
      <Text variant="title-sm" className="mb-2">{t_i18n('Members')}</Text>
      <GraphClusterMembers clusterId={cluster.id} />
      {promotion && (
        <GraphClusterPromoteDialog
          clusterId={cluster.id}
          clusterName={cluster.name}
          target={promotion}
          onClose={() => setPromotion(null)}
        />
      )}
    </div>
  );
};

const RootGraphCluster = () => {
  const { clusterId } = useParams() as { clusterId: string };
  const queryRef = useQueryLoading<RootGraphClusterQuery>(graphClusterQuery, { id: clusterId });
  return queryRef ? (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <GraphClusterComponent queryRef={queryRef} />
    </Suspense>
  ) : null;
};

export default RootGraphCluster;
