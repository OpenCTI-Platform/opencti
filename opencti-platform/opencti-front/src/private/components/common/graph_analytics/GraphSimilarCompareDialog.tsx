import React, { ReactNode, Suspense, useEffect } from 'react';
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
import GraphSimilarityScore from './GraphSimilarityScore';
import GraphRelativeTime from './GraphRelativeTime';
import { GRAPH_CLUSTERS_PATH, recordGraphAnalyticsPivot } from './graphAnalyticsUtils';
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

interface CompareRow {
  label: string;
  render: (entity: ComparedEntity) => ReactNode;
}

const EntityHeader = ({ entity }: { entity: ComparedEntity }) => {
  const { translateEntityType } = useEntityTranslation();
  const link = `${resolveLink(entity.entity_type)}/${entity.id}`;
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, minWidth: 0 }} data-testid="graph-compare-column">
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
        <ItemIcon type={entity.entity_type} />
        <Link to={link} target="_blank" rel="noopener noreferrer" onClick={() => recordGraphAnalyticsPivot('similar_open')}>
          <Text variant="content-base-bold" as="span">{entity.representative.main}</Text>
        </Link>
      </Box>
      <Text variant="content-caption" as="span">{translateEntityType(entity.entity_type)}</Text>
    </Box>
  );
};

/**
 * Both entities side by side on one grid, so each value lines up with its counterpart. A row is shown when at least
 * one entity has a value; the other then reads "Not recorded".
 */
const CompareGrid = ({ source, target }: { source: ComparedEntity; target: ComparedEntity }) => {
  const { t_i18n } = useFormatter();
  const rows: CompareRow[] = [
    {
      label: t_i18n('Description'),
      render: (entity) => entity.representative.secondary && (
        <Text variant="content-compact" style={{ display: '-webkit-box', WebkitLineClamp: 4, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
          {entity.representative.secondary}
        </Text>
      ),
    },
    { label: t_i18n('Author'), render: (entity) => entity.createdBy?.name },
    {
      label: t_i18n('Platform creation date'),
      render: (entity) => entity.created_at && <GraphRelativeTime date={entity.created_at} />,
    },
    {
      label: t_i18n('Graph degree'),
      render: (entity) => (entity.x_opencti_graph_metrics?.degree != null
        ? t_i18n('{count, plural, one {# relationship} other {# relationships}}', { values: { count: entity.x_opencti_graph_metrics.degree } })
        : null),
    },
    {
      label: t_i18n('Graph cluster'),
      render: (entity) => entity.x_opencti_graph_metrics?.cluster_id && (
        <Link to={`${GRAPH_CLUSTERS_PATH}/${entity.x_opencti_graph_metrics.cluster_id}`}>
          {t_i18n('{count, plural, one {Cluster of # member} other {Cluster of # members}}', { values: { count: entity.x_opencti_graph_metrics.cluster_size ?? 0 } })}
        </Link>
      ),
    },
    {
      label: t_i18n('Markings'),
      render: (entity) => (entity.objectMarking ?? []).length > 0 && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {(entity.objectMarking ?? []).map((marking) => (
            <Chip key={marking.id} label={marking.definition ?? ''} color={marking.x_opencti_color ?? undefined} />
          ))}
        </Box>
      ),
    },
    {
      label: t_i18n('Labels'),
      render: (entity) => (entity.objectLabel ?? []).length > 0 && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {(entity.objectLabel ?? []).map((label) => (
            <Chip key={label.id} label={label.value ?? ''} color={label.color ?? undefined} />
          ))}
        </Box>
      ),
    },
  ];
  const cell = (value: ReactNode) => (value ? <Box sx={{ minWidth: 0 }}>{value}</Box> : <Text variant="content-caption">{t_i18n('Not recorded')}</Text>);
  return (
    <Box
      sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '160px minmax(0, 1fr) minmax(0, 1fr)' }, columnGap: 3, rowGap: 1.5, alignItems: 'start' }}
      data-testid="graph-compare-grid"
    >
      <Box sx={{ display: { xs: 'none', sm: 'block' } }} />
      <EntityHeader entity={source} />
      <EntityHeader entity={target} />
      {rows.map(({ label, render }) => {
        const values = [render(source), render(target)];
        if (!values.some(Boolean)) return null;
        return (
          <React.Fragment key={label}>
            <Text variant="content-caption">{label}</Text>
            {cell(values[0])}
            {cell(values[1])}
          </React.Fragment>
        );
      })}
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
      <CompareGrid source={source} target={target} />
      <Divider />
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
        <GraphSimilarityScore score={similar.score} jaccard={similar.jaccard} structural={similar.structural} />
        <Text variant="content-compact" as="span">
          {t_i18n('{count, plural, one {# shared element} other {# shared elements}}', { values: { count: similar.shared_count } })}
        </Text>
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
