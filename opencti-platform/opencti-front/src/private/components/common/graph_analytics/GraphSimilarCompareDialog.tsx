import React, { Suspense, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Chip, Text } from '@filigran/design-system';
import { Box, Divider } from '@mui/material';
import Dialog from '@common/dialog/Dialog';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import { resolveLink } from '../../../../utils/Entity';
import GraphSimilarityEvidence from './GraphSimilarityEvidence';
import { formatSimilarityScore, GRAPH_CLUSTERS_PATH, recordGraphAnalyticsPivot } from './graphAnalyticsUtils';
import type { SimilarEntityNode } from './StixCoreObjectSimilar';
import type { GraphSimilarCompareDialogQuery, GraphSimilarCompareDialogQuery$data } from './__generated__/GraphSimilarCompareDialogQuery.graphql';

const compareQuery = graphql`
  query GraphSimilarCompareDialogQuery($sourceId: String!, $targetId: String!) {
    source: stixCoreObject(id: $sourceId) {
      id
      entity_type
      created_at
      representative {
        main
        secondary
      }
      createdBy {
        ... on Identity {
          name
        }
      }
      objectMarking {
        id
        definition
        x_opencti_color
      }
      objectLabel {
        id
        value
        color
      }
      x_opencti_graph_metrics {
        degree
        betweenness_approx
        cluster_id
        cluster_size
      }
    }
    target: stixCoreObject(id: $targetId) {
      id
      entity_type
      created_at
      representative {
        main
        secondary
      }
      createdBy {
        ... on Identity {
          name
        }
      }
      objectMarking {
        id
        definition
        x_opencti_color
      }
      objectLabel {
        id
        value
        color
      }
      x_opencti_graph_metrics {
        degree
        betweenness_approx
        cluster_id
        cluster_size
      }
    }
  }
`;

type ComparedEntity = NonNullable<GraphSimilarCompareDialogQuery$data['source']>;

const EntityColumn = ({ entity }: { entity: ComparedEntity }) => {
  const { t_i18n, fldt } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const metrics = entity.x_opencti_graph_metrics;
  const link = `${resolveLink(entity.entity_type)}/${entity.id}`;
  return (
    <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="graph-compare-column">
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <ItemIcon type={entity.entity_type} />
        <Link to={link} target="_blank" rel="noopener noreferrer" onClick={() => recordGraphAnalyticsPivot('similar_open')}>
          <Text variant="content-base-bold" as="span">{entity.representative.main}</Text>
        </Link>
      </Box>
      <Chip label={translateEntityType(entity.entity_type)} />
      <Text variant="content-compact" style={{ display: '-webkit-box', WebkitLineClamp: 4, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
        {entity.representative.secondary || t_i18n('No description')}
      </Text>
      <Text variant="content-compact">{`${t_i18n('Author')}: ${entity.createdBy?.name ?? '-'}`}</Text>
      <Text variant="content-compact">{`${t_i18n('Platform creation date')}: ${fldt(entity.created_at)}`}</Text>
      <Text variant="content-compact">{`${t_i18n('Graph degree')}: ${metrics?.degree ?? '-'}`}</Text>
      {metrics?.cluster_id && (
        <Text variant="content-compact">
          {`${t_i18n('Graph cluster')}: `}
          <Link to={`${GRAPH_CLUSTERS_PATH}/${metrics.cluster_id}`}>
            {`${metrics.cluster_size ?? '-'} ${t_i18n('members')}`}
          </Link>
        </Text>
      )}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
        {(entity.objectMarking ?? []).map((marking) => (
          <Chip key={marking.id} label={marking.definition ?? ''} color={marking.x_opencti_color ?? undefined} />
        ))}
        {(entity.objectLabel ?? []).map((label) => (
          <Chip key={label.id} label={label.value ?? ''} color={label.color ?? undefined} />
        ))}
      </Box>
    </Box>
  );
};

interface CompareContentProps {
  queryRef: PreloadedQuery<GraphSimilarCompareDialogQuery>;
  similar: SimilarEntityNode;
}

const CompareContent = ({ queryRef, similar }: CompareContentProps) => {
  const { t_i18n } = useFormatter();
  const { source, target } = usePreloadedQuery(compareQuery, queryRef);
  if (!source || !target) {
    return <Text variant="content-base">{t_i18n('One of the entities is no longer accessible')}</Text>;
  }
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Box sx={{ display: 'flex', gap: 3 }}>
        <EntityColumn entity={source} />
        <Divider orientation="vertical" flexItem />
        <EntityColumn entity={target} />
      </Box>
      <Divider />
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
        <Chip label={`${t_i18n('Similarity')} ${formatSimilarityScore(similar.score)}`} severity="info" />
        <Chip label={`${t_i18n('Weighted Jaccard')} ${formatSimilarityScore(similar.jaccard)}`} />
        <Chip label={`${t_i18n('Structural similarity')} ${formatSimilarityScore(similar.structural)}`} />
        <Chip label={`${t_i18n('Shared elements')} ${similar.shared_count}`} />
      </Box>
      <Text variant="title-sm">{t_i18n('Shared evidence')}</Text>
      <GraphSimilarityEvidence evidence={similar.evidence} maxPerFamily={20} />
    </Box>
  );
};

interface GraphSimilarCompareDialogProps {
  sourceId: string;
  similar: SimilarEntityNode;
  onClose: () => void;
}

/** Side by side view of an entity and one of its look-alikes, with the evidence the score is built on. */
const GraphSimilarCompareDialog = ({ sourceId, similar, onClose }: GraphSimilarCompareDialogProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<GraphSimilarCompareDialogQuery>(compareQuery, { sourceId, targetId: similar.entity.id });
  useEffect(() => {
    recordGraphAnalyticsPivot('similar_compare');
  }, [similar.entity.id]);
  return (
    <Dialog open onClose={onClose} size="large" title={t_i18n('Compare side by side')} showCloseButton>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <CompareContent queryRef={queryRef} similar={similar} />
        </Suspense>
      )}
    </Dialog>
  );
};

export default GraphSimilarCompareDialog;
