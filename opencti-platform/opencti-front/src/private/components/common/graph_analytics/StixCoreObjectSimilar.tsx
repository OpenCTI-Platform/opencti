import React, { Suspense, useState } from 'react';
import { createPortal } from 'react-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import {
  Chip,
  IconButton,
  ProgressBar,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Switch,
  Text,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import { Alert, Box } from '@mui/material';
import { CompareArrowsOutlined, OpenInNewOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { INVESTIGATION_INUPDATE, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { resolveLink } from '../../../../utils/Entity';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import GraphSimilarityEvidence from './GraphSimilarityEvidence';
import GraphSimilarCompareDialog from './GraphSimilarCompareDialog';
import GraphSimilarityScore from './GraphSimilarityScore';
import GraphRelativeTime from './GraphRelativeTime';
import useGraphAnalyticsInvestigation from './useGraphAnalyticsInvestigation';
import { formatSimilarityScore, recordGraphAnalyticsPivot, reportPayloadErrors } from './graphAnalyticsUtils';
import { MESSAGING$ } from '../../../../relay/environment';
import type { StixCoreObjectSimilarQuery, StixCoreObjectSimilarQuery$data } from './__generated__/StixCoreObjectSimilarQuery.graphql';
import type { StixCoreObjectSimilarRecomputeMutation } from './__generated__/StixCoreObjectSimilarRecomputeMutation.graphql';

export const stixCoreObjectSimilarQuery = graphql`
  query StixCoreObjectSimilarQuery($id: String!, $first: Int, $minScore: Float, $onlyWithSecurityCoverage: Boolean) {
    stixCoreObject(id: $id) {
      id
      entity_type
      representative {
        main
      }
    }
    similarEntities(id: $id, first: $first, minScore: $minScore, onlyWithSecurityCoverage: $onlyWithSecurityCoverage) {
      edges {
        node {
          id
          score
          jaccard
          structural
          computed_at
          shared_count
          entity {
            id
            entity_type
            representative {
              main
              secondary
            }
          }
          evidence {
            family
            entities {
              id
              entity_type
              representative {
                main
              }
            }
          }
          securityCoverage {
            id
            representative {
              main
            }
          }
        }
      }
    }
  }
`;

const recomputeMutation = graphql`
  mutation StixCoreObjectSimilarRecomputeMutation($ids: [String!]!) {
    graphAnalyticsRequestRecompute(ids: $ids)
  }
`;

const MIN_SCORES = ['0', '0.2', '0.4', '0.6', '0.8'];
const PAGE_SIZE = 25;

export type SimilarEntityNode = NonNullable<StixCoreObjectSimilarQuery$data['similarEntities']>['edges'][number]['node'];

interface StixCoreObjectSimilarComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectSimilarQuery>;
  // toolbar element receiving the actions that need the results, so every control sits on one row
  actionsSlot: HTMLElement | null;
}

const StixCoreObjectSimilarComponent = ({ queryRef, actionsSlot }: StixCoreObjectSimilarComponentProps) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const canInvestigate = useGranted([INVESTIGATION_INUPDATE]);
  const { startInvestigation, inFlight } = useGraphAnalyticsInvestigation();
  const [compared, setCompared] = useState<SimilarEntityNode | null>(null);
  const { stixCoreObject, similarEntities } = usePreloadedQuery(stixCoreObjectSimilarQuery, queryRef);
  if (!stixCoreObject) return null;
  const nodes = (similarEntities?.edges ?? []).map((edge) => edge.node);

  if (nodes.length === 0) {
    return (
      <Alert severity="info" variant="outlined" data-testid="graph-similar-empty">
        {t_i18n('No similar entity found yet. Similarity is computed in the background from the shared techniques, tools, malware, infrastructure, victims or co-occurrences, and refreshed when the knowledge changes.')}
      </Alert>
    );
  }

  const handleInvestigate = () => {
    const ids = [
      stixCoreObject.id,
      ...nodes.map((node) => node.entity.id),
      ...nodes.flatMap((node) => node.evidence.flatMap((family) => family.entities.map((entity) => entity.id))),
    ];
    startInvestigation(t_i18n('Similar to {name}', { values: { name: stixCoreObject.representative.main } }), ids, 'similar_investigation');
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="graph-similar-list">
      {canInvestigate && actionsSlot && createPortal(
        <Button variant="secondary" onClick={handleInvestigate} disabled={inFlight}>
          {t_i18n('Investigate these similar entities')}
        </Button>,
        actionsSlot,
      )}
      {nodes.map((node) => {
        const link = `${resolveLink(node.entity.entity_type)}/${node.entity.id}`;
        const percentage = Math.round(node.score * 100);
        return (
          <Card key={node.id} padding="medium">
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }} data-testid="graph-similar-item">
              <ItemIcon type={node.entity.entity_type} />
              <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                  <Link to={link} onClick={() => recordGraphAnalyticsPivot('similar_open')}>
                    <Text variant="content-base-bold" as="span">{node.entity.representative.main}</Text>
                  </Link>
                  <Chip label={translateEntityType(node.entity.entity_type)} />
                  <GraphSimilarityScore score={node.score} jaccard={node.jaccard} structural={node.structural} />
                  {node.securityCoverage && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Link to={`/dashboard/analyses/security_coverages/${node.securityCoverage.id}`}>
                          <Chip label={t_i18n('OpenAEV scenario available')} severity="info" />
                        </Link>
                      </TooltipTrigger>
                      <TooltipContent>{node.securityCoverage.representative.main}</TooltipContent>
                    </Tooltip>
                  )}
                </Box>
                <ProgressBar value={percentage} aria-label={t_i18n('Similarity with {name}', { values: { name: node.entity.representative.main } })} />
                <Text variant="content-caption" data-testid="graph-similar-meta">
                  {t_i18n('{count, plural, one {# shared element} other {# shared elements}}', { values: { count: node.shared_count } })}
                  {node.computed_at && (
                    <>
                      {' - '}
                      <GraphRelativeTime date={node.computed_at} template="computed {time}" />
                    </>
                  )}
                </Text>
                <GraphSimilarityEvidence evidence={node.evidence} />
              </Box>
              <Box sx={{ display: 'flex', gap: 0.5 }}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <IconButton
                      aria-label={t_i18n('Compare side by side')}
                      priority="tertiary"
                      icon={<CompareArrowsOutlined fontSize="small" />}
                      onClick={() => setCompared(node)}
                    />
                  </TooltipTrigger>
                  <TooltipContent>{t_i18n('Compare side by side')}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <IconButton
                      aria-label={t_i18n('Open in a new tab')}
                      priority="tertiary"
                      icon={<OpenInNewOutlined fontSize="small" />}
                      onClick={() => {
                        recordGraphAnalyticsPivot('similar_open');
                        window.open(link, '_blank', 'noopener,noreferrer');
                      }}
                    />
                  </TooltipTrigger>
                  <TooltipContent>{t_i18n('Open in a new tab')}</TooltipContent>
                </Tooltip>
              </Box>
            </Box>
          </Card>
        );
      })}
      {compared && (
        <GraphSimilarCompareDialog
          sourceId={stixCoreObject.id}
          similar={compared}
          onClose={() => setCompared(null)}
        />
      )}
    </Box>
  );
};

interface StixCoreObjectSimilarProps {
  stixCoreObjectId: string;
}

/** "Similar" tab of an entity: precomputed look-alikes with their score and the shared evidence, filtered for the user. */
const StixCoreObjectSimilar = ({ stixCoreObjectId }: StixCoreObjectSimilarProps) => {
  const { t_i18n } = useFormatter();
  const canRecompute = useGranted([KNOWLEDGE_KNUPDATE]);
  const [minScore, setMinScore] = useState('0');
  const [onlyWithSecurityCoverage, setOnlyWithSecurityCoverage] = useState(false);
  const [actionsSlot, setActionsSlot] = useState<HTMLElement | null>(null);
  const [commitRecompute, recomputing] = useApiMutation<StixCoreObjectSimilarRecomputeMutation>(recomputeMutation);
  const queryRef = useQueryLoading<StixCoreObjectSimilarQuery>(stixCoreObjectSimilarQuery, {
    id: stixCoreObjectId,
    first: PAGE_SIZE,
    minScore: Number(minScore),
    onlyWithSecurityCoverage,
  });
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="graph-similar-tab">
      <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: 2, flexWrap: 'wrap' }} data-testid="graph-similar-toolbar">
        <Box sx={{ width: 200 }}>
          <Select value={minScore} onValueChange={setMinScore}>
            <SelectLabel>{t_i18n('Minimum similarity')}</SelectLabel>
            <SelectTrigger aria-label={t_i18n('Minimum similarity')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Minimum similarity')}>
              {MIN_SCORES.map((value) => (
                <SelectItem key={value} value={value}>
                  {value === '0' ? t_i18n('Any') : formatSimilarityScore(Number(value))}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Box>
        <Switch
          checked={onlyWithSecurityCoverage}
          onCheckedChange={setOnlyWithSecurityCoverage}
          label={t_i18n('Only with an OpenAEV scenario')}
        />
        <Box sx={{ flex: 1 }} />
        {canRecompute && (
          <Button
            variant="tertiary"
            disabled={recomputing}
            onClick={() => commitRecompute({
              variables: { ids: [stixCoreObjectId] },
              onCompleted: (_, errors) => {
                if (reportPayloadErrors(errors)) return;
                MESSAGING$.notifySuccess(t_i18n('The similarity of this entity will be refreshed in the next minutes'));
              },
            })}
          >
            {t_i18n('Refresh similarity')}
          </Button>
        )}
        <Box ref={setActionsSlot} sx={{ display: 'flex' }} />
      </Box>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixCoreObjectSimilarComponent queryRef={queryRef} actionsSlot={actionsSlot} />
        </Suspense>
      )}
    </Box>
  );
};

export default StixCoreObjectSimilar;
