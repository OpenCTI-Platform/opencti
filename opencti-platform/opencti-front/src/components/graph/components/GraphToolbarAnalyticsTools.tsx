import React, { Suspense, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { CompareArrowsOutlined, GridOnOutlined, RouteOutlined } from '@mui/icons-material';
import { Alert, Checkbox, Chip, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import StixPathFinder, { type StixPathResult } from '@components/common/graph_analytics/StixPathFinder';
import GraphSimilarityMatrix from '@components/common/graph_analytics/GraphSimilarityMatrix';
import GraphSimilarityEvidence from '@components/common/graph_analytics/GraphSimilarityEvidence';
import { formatSimilarityScore, recordGraphAnalyticsPivot, similarityScoreSeverity } from '@components/common/graph_analytics/graphAnalyticsUtils';
import GraphToolbarItem from './GraphToolbarItem';
import { expandRelationshipsQuery } from './GraphToolbarExpandTools';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';
import { fetchQuery } from '../../../relay/environment';
import Loader, { LoaderVariant } from '../../Loader';
import ItemIcon from '../../ItemIcon';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
import type { ObjectToParse } from '../utils/useGraphParser';
import type { GraphToolbarExpandToolsRelationshipsQuery, GraphToolbarExpandToolsRelationshipsQuery$data } from './__generated__/GraphToolbarExpandToolsRelationshipsQuery.graphql';
import type { GraphToolbarAnalyticsToolsSimilarQuery, GraphToolbarAnalyticsToolsSimilarQuery$data } from './__generated__/GraphToolbarAnalyticsToolsSimilarQuery.graphql';
import type { GraphToolbarAnalyticsToolsObjectsQuery, GraphToolbarAnalyticsToolsObjectsQuery$data } from './__generated__/GraphToolbarAnalyticsToolsObjectsQuery.graphql';
import type { GraphToolbarAnalyticsToolsMatrixQuery, GraphToolbarAnalyticsToolsMatrixQuery$data } from './__generated__/GraphToolbarAnalyticsToolsMatrixQuery.graphql';

const similarQuery = graphql`
  query GraphToolbarAnalyticsToolsSimilarQuery($id: String!, $first: Int, $minScore: Float) {
    similarEntities(id: $id, first: $first, minScore: $minScore) {
      edges {
        node {
          id
          score
          shared_count
          entity {
            id
            entity_type
            representative {
              main
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
        }
      }
    }
  }
`;

const matrixQuery = graphql`
  query GraphToolbarAnalyticsToolsMatrixQuery($ids: [String!]) {
    graphSimilarityMatrix(ids: $ids) {
      entities {
        id
        entity_type
        representative {
          main
        }
      }
      cells {
        source_id
        target_id
        score
        shared_count
      }
    }
  }
`;

// Same entity fields as the investigation canvas query, so added entities render like the others
const objectsQuery = graphql`
  query GraphToolbarAnalyticsToolsObjectsQuery($filters: FilterGroup, $count: Int) {
    stixCoreObjects(filters: $filters, first: $count) {
      edges {
        node {
          id
          entity_type
          parent_types
          created_at
          updated_at
          numberOfConnectedElement
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ... on StixDomainObject {
            created
          }
          ... on AttackPattern {
            name
            x_mitre_id
          }
          ... on Campaign {
            name
            first_seen
            last_seen
          }
          ... on CourseOfAction {
            name
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            published
          }
          ... on Grouping {
            name
            description
          }
          ... on Individual {
            name
          }
          ... on Organization {
            name
          }
          ... on Sector {
            name
          }
          ... on System {
            name
          }
          ... on Indicator {
            name
            valid_from
          }
          ... on Infrastructure {
            name
          }
          ... on IntrusionSet {
            name
            first_seen
            last_seen
          }
          ... on Position {
            name
          }
          ... on City {
            name
          }
          ... on AdministrativeArea {
            name
          }
          ... on Country {
            name
          }
          ... on Region {
            name
          }
          ... on Malware {
            name
            first_seen
            last_seen
          }
          ... on MalwareAnalysis {
            result_name
          }
          ... on ThreatActor {
            name
            first_seen
            last_seen
          }
          ... on Tool {
            name
          }
          ... on Vulnerability {
            name
          }
          ... on Incident {
            name
            first_seen
            last_seen
          }
          ... on Event {
            name
            start_time
            stop_time
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on Task {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on StixFile {
            observableName: name
            hashes {
              algorithm
              hash
            }
          }
        }
      }
    }
  }
`;

const idsFilter = (ids: string[]) => ({
  mode: 'and' as const,
  filterGroups: [],
  filters: [{ key: ['ids'], values: ids }],
});

// Similar entities are looked up for the first selected nodes only, to keep the dialog readable
const SIMILAR_MAX_SOURCES = 5;
const SIMILAR_PER_SOURCE = 10;
const MATRIX_MAX_ENTITIES = 25;
const MIN_SCORES = ['0', '0.2', '0.4', '0.6'];

type SimilarNode = NonNullable<GraphToolbarAnalyticsToolsSimilarQuery$data['similarEntities']>['edges'][number]['node'];
interface SimilarGroup {
  sourceId: string;
  sourceLabel: string;
  nodes: SimilarNode[];
}

interface GraphToolbarAnalyticsToolsProps {
  onInvestigationExpand?: (newObjects: ObjectToParse[]) => void;
}

/** Graph analytics on the investigation canvas: paths between two nodes, look-alikes and pairwise similarity. */
const GraphToolbarAnalyticsTools = ({ onInvestigationExpand }: GraphToolbarAnalyticsToolsProps) => {
  const { t_i18n } = useFormatter();
  const { rawObjects, graphState: { selectedNodes } } = useGraphContext();
  const { setLinearProgress } = useGraphInteractions();
  const [pathOpen, setPathOpen] = useState(false);
  const [similarOpen, setSimilarOpen] = useState(false);
  const [matrixOpen, setMatrixOpen] = useState(false);
  const [minScore, setMinScore] = useState('0');
  const [similarGroups, setSimilarGroups] = useState<SimilarGroup[] | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [matrix, setMatrix] = useState<NonNullable<GraphToolbarAnalyticsToolsMatrixQuery$data['graphSimilarityMatrix']> | null>(null);
  const [adding, setAdding] = useState(false);
  const [similarFailed, setSimilarFailed] = useState(false);
  const [matrixFailed, setMatrixFailed] = useState(false);

  const rawById = new Map(rawObjects.map((o) => [o.id, o]));
  // the node name carries a second line with the date of the object
  const nodeLabel = (node: { id: string; label?: string }) => {
    const raw = rawById.get(node.id);
    return raw ? getMainRepresentative(raw, node.label || node.id) : (node.label || node.id);
  };
  const existingIds = new Set(rawById.keys());

  // Each request only applies its result while it is the latest one, and a failure is shown in place of the loader
  useEffect(() => {
    if (!similarOpen) return undefined;
    let latest = true;
    const sources = selectedNodes.slice(0, SIMILAR_MAX_SOURCES);
    setSimilarGroups(null);
    setSimilarFailed(false);
    Promise.all(sources.map(async (source) => {
      const data = await fetchQuery<GraphToolbarAnalyticsToolsSimilarQuery>(similarQuery, {
        id: source.id,
        first: SIMILAR_PER_SOURCE,
        minScore: Number(minScore),
      }).toPromise();
      const nodes = (data?.similarEntities?.edges ?? []).map((edge) => edge.node);
      return { sourceId: source.id, sourceLabel: nodeLabel(source), nodes };
    })).then((groups) => {
      if (!latest) return;
      setSimilarGroups(groups);
      const candidates = groups.flatMap((group) => group.nodes.map((node) => node.entity.id)).filter((id) => !existingIds.has(id));
      setChecked(new Set(candidates));
    }).catch(() => {
      if (latest) setSimilarFailed(true);
    });
    return () => {
      latest = false;
    };
  }, [similarOpen, minScore]);

  useEffect(() => {
    if (!matrixOpen) return undefined;
    let latest = true;
    setMatrix(null);
    setMatrixFailed(false);
    fetchQuery<GraphToolbarAnalyticsToolsMatrixQuery>(matrixQuery, {
      ids: selectedNodes.slice(0, MATRIX_MAX_ENTITIES).map((node) => node.id),
    }).toPromise().then((data) => {
      if (latest) setMatrix(data?.graphSimilarityMatrix ?? { entities: [], cells: [] });
    }).catch(() => {
      if (latest) setMatrixFailed(true);
    });
    return () => {
      latest = false;
    };
  }, [matrixOpen]);

  const addPaths = async (paths: StixPathResult[]) => {
    const relationshipIds = Array.from(new Set(paths.flatMap((path) => path.relationship_ids)));
    if (relationshipIds.length === 0) return;
    setAdding(true);
    setLinearProgress(true);
    try {
      const data = await fetchQuery<GraphToolbarExpandToolsRelationshipsQuery>(
        expandRelationshipsQuery,
        { filters: idsFilter(relationshipIds) },
      ).toPromise() as GraphToolbarExpandToolsRelationshipsQuery$data;
      const added = new Set(existingIds);
      const newObjects: ObjectToParse[] = [];
      (data?.stixRelationships?.edges ?? []).forEach((edge) => {
        if (!edge) return;
        [edge.node.from, edge.node.to, edge.node].forEach((element) => {
          if (element?.id && !added.has(element.id)) {
            added.add(element.id);
            newObjects.push(element as unknown as ObjectToParse);
          }
        });
      });
      if (newObjects.length > 0) onInvestigationExpand?.(newObjects);
      recordGraphAnalyticsPivot('path_expand');
      setPathOpen(false);
    } finally {
      setAdding(false);
      setLinearProgress(false);
    }
  };

  const addSimilar = async () => {
    const ids = Array.from(checked).filter((id) => !existingIds.has(id));
    if (ids.length === 0) return;
    setAdding(true);
    setLinearProgress(true);
    try {
      const data = await fetchQuery<GraphToolbarAnalyticsToolsObjectsQuery>(
        objectsQuery,
        { filters: idsFilter(ids), count: ids.length },
      ).toPromise() as GraphToolbarAnalyticsToolsObjectsQuery$data;
      const newObjects = (data?.stixCoreObjects?.edges ?? []).map((edge) => edge.node as unknown as ObjectToParse);
      if (newObjects.length > 0) onInvestigationExpand?.(newObjects);
      recordGraphAnalyticsPivot('similar_investigation');
      setSimilarOpen(false);
    } finally {
      setAdding(false);
      setLinearProgress(false);
    }
  };

  const toggle = (id: string) => {
    const next = new Set(checked);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setChecked(next);
  };

  const [from, to] = selectedNodes;
  return (
    <>
      <GraphToolbarItem
        Icon={<RouteOutlined />}
        color="primary"
        onClick={() => setPathOpen(true)}
        title={t_i18n('Find path between the two selected entities')}
        disabled={selectedNodes.length !== 2}
      />
      <GraphToolbarItem
        Icon={<CompareArrowsOutlined />}
        color="primary"
        onClick={() => setSimilarOpen(true)}
        title={t_i18n('Expand by similarity')}
        disabled={selectedNodes.length === 0}
      />
      <GraphToolbarItem
        Icon={<GridOnOutlined />}
        color="primary"
        onClick={() => setMatrixOpen(true)}
        title={t_i18n('Similarity matrix of the selected entities')}
        disabled={selectedNodes.length < 2}
      />

      {pathOpen && from && to && (
        <Dialog open onClose={() => setPathOpen(false)} size="large" title={t_i18n('Find path')} showCloseButton>
          <StixPathFinder
            fromId={from.id}
            fromLabel={nodeLabel(from)}
            toId={to.id}
            toLabel={nodeLabel(to)}
            renderActions={(_, selectedPaths) => (
              <Button disabled={selectedPaths.length === 0 || adding} onClick={() => addPaths(selectedPaths)}>
                {t_i18n('Add the selected paths to the graph')}
              </Button>
            )}
          />
        </Dialog>
      )}

      {similarOpen && (
        <Dialog open onClose={() => setSimilarOpen(false)} size="large" title={t_i18n('Expand by similarity')} showCloseButton>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="graph-expand-similarity">
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
            {selectedNodes.length > SIMILAR_MAX_SOURCES && (
              <Alert severity="info" elevation={1} title={t_i18n('Only the first five selected entities are used.')} />
            )}
            {similarFailed && (
              <Alert severity="error" elevation={1} title={t_i18n('The similar entities could not be loaded.')} />
            )}
            {!similarFailed && similarGroups === null && <Loader variant={LoaderVariant.inElement} />}
            {(similarGroups ?? []).map((group) => (
              <Box key={group.sourceId} sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Text variant="title-sm">{t_i18n('Similar to {name}', { values: { name: group.sourceLabel } })}</Text>
                {group.nodes.length === 0 && <Text variant="content-compact">{t_i18n('No similar entity found yet.')}</Text>}
                {group.nodes.map((node) => {
                  const inGraph = existingIds.has(node.entity.id);
                  return (
                    <Box key={node.id} sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                      <Checkbox
                        checked={inGraph || checked.has(node.entity.id)}
                        disabled={inGraph}
                        onCheckedChange={() => toggle(node.entity.id)}
                        aria-label={node.entity.representative.main}
                      />
                      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <ItemIcon type={node.entity.entity_type} size="small" />
                          <Text variant="content-base">{node.entity.representative.main}</Text>
                          <Chip
                            label={t_i18n('{score} similar', { values: { score: formatSimilarityScore(node.score) } })}
                            severity={similarityScoreSeverity(node.score)}
                          />
                          {inGraph && <Chip label={t_i18n('Already in the graph')} />}
                        </Box>
                        <GraphSimilarityEvidence evidence={node.evidence} maxPerFamily={4} dense />
                      </Box>
                    </Box>
                  );
                })}
              </Box>
            ))}
            <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button disabled={adding || Array.from(checked).every((id) => existingIds.has(id))} onClick={addSimilar}>
                {t_i18n('Add to the graph')}
              </Button>
            </Box>
          </Box>
        </Dialog>
      )}

      {matrixOpen && (
        <Dialog open onClose={() => setMatrixOpen(false)} size="large" title={t_i18n('Similarity matrix')} showCloseButton>
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            {matrixFailed && (
              <Alert severity="error" elevation={1} title={t_i18n('The similarity matrix could not be loaded.')} />
            )}
            {!matrixFailed && matrix === null && <Loader variant={LoaderVariant.inElement} />}
            {matrix !== null && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                {selectedNodes.length > MATRIX_MAX_ENTITIES && (
                  <Alert severity="info" elevation={1} title={t_i18n('Only the first 25 selected entities are compared.')} />
                )}
                <GraphSimilarityMatrix entities={matrix.entities} cells={matrix.cells} />
              </Box>
            )}
          </Suspense>
        </Dialog>
      )}
    </>
  );
};

export default GraphToolbarAnalyticsTools;
