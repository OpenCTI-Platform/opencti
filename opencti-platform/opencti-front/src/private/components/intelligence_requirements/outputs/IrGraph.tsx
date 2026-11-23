import React, { startTransition, useMemo, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import { Checkbox, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import SimpleGraph2D from '../../../../components/graph/SimpleGraph2D';
import useGraphParser, { type ObjectToParse } from '../../../../components/graph/utils/useGraphParser';
import type { GraphLink, GraphNode } from '../../../../components/graph/graph.types';
import type { GraphRef2D } from '../../../../components/graph/GraphContext';
import { IrMultiSelect, IrSelect } from '../configuration/IrFields';
import IrMatchDrawer, { type IrMatchData } from './IrMatchDrawer';
import { ScoreBar } from './IrOutputCommon';
import { buildProofGraph, KEYWORD_RELATIONSHIP, type ProofGraphNode, sharedEntities } from './irProofGraph';
import type { IrGraphQuery } from './__generated__/IrGraphQuery.graphql';

// Graph view of a requirement: its entities and the proofs that brought them in (starting points, relationships,
// containers, keywords). It shows what the list cannot: entities shared by several starting points, chains of two hops,
// a criterion that brings a whole cluster, a starting point that brings nothing.

const graphQuery = graphql`
  query IrGraphQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_thresholds
      ir_scope_criteria { id name kind mode from_group_ids from_in_requirement }
    }
    intelligenceRequirementMatches(id: $id, first: 1000, statuses: [auto, accepted, proposed], orderBy: match_score, orderMode: desc) {
      edges {
        node {
          id
          match_status
          match_score
          match_excluded
          match_entity_type
          match_entity_id
          match_criteria_ids
          match_last_fact_at
          entity { ... on StixCoreObject { representative { main } } }
          match_explanations {
            criterion_id
            kind
            anchor_id
            anchor_type
            relationship_type
            direction
            keyword
            field
            container_id
            container_type
            anchor { representative { main } }
            container { representative { main } }
          }
          match_score_breakdown { name points hit reason kind criterion_id }
        }
      }
    }
  }
`;

const LIMITS = [50, 100, 200, 500];

// Pulls every node towards the centre, so that the separate clusters (one per starting point) stay close and readable
const gravity = (strength: number) => {
  let nodes: { x?: number; y?: number; vx?: number; vy?: number }[] = [];
  const force = (alpha: number) => nodes.forEach((n) => {
    n.vx = (n.vx ?? 0) - (n.x ?? 0) * strength * alpha;
    n.vy = (n.vy ?? 0) - (n.y ?? 0) * strength * alpha;
  });
  force.initialize = (initial: typeof nodes) => {
    nodes = initial;
  };
  return force;
};
const SHARED_SHOWN = 12;

const IrGraph = ({ irId }: { irId: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const theme = useTheme(); // the MUI theme: its palette colours are resolved strings
  const { buildNode, buildLink } = useGraphParser();
  const parentRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<GraphRef2D | null>(null);
  const [fetchKey, setFetchKey] = useState(0);
  const data = useLazyLoadQuery<IrGraphQuery>(graphQuery, { id: irId }, { fetchPolicy: 'network-only', fetchKey });
  const criteria = data.intelligenceRequirement?.ir_scope_criteria ?? [];
  const thresholds = [...(data.intelligenceRequirement?.ir_thresholds ?? [])].sort((a, b) => a - b);
  const matches = useMemo(() => (data.intelligenceRequirementMatches?.edges ?? []).map((e) => e.node), [data]);

  const [minScore, setMinScore] = useState(0);
  const [types, setTypes] = useState<string[]>([]);
  const [criterionIds, setCriterionIds] = useState<string[]>([]);
  const [includeProposed, setIncludeProposed] = useState(false);
  const [limit, setLimit] = useState(100);
  const [selected, setSelected] = useState<string | null>(null);

  const graph = useMemo(
    () => buildProofGraph(matches, { minScore, types, criteria: criterionIds, includeProposed, limit }),
    [matches, minScore, types, criterionIds, includeProposed, limit],
  );
  const shared = sharedEntities(graph);
  const counts = {
    entities: graph.nodes.filter((n) => n.kind === 'entity').length,
    subjects: graph.nodes.filter((n) => n.kind === 'anchor').length,
    texts: graph.nodes.filter((n) => n.kind === 'container' || n.kind === 'keyword').length,
  };

  // One colour per role in the requirement; the icon keeps showing the type of the entity
  const ROLE_COLORS: Record<ProofGraphNode['kind'], string> = {
    anchor: theme.palette.warning.main,
    entity: theme.palette.primary.main,
    container: theme.palette.text.secondary,
    keyword: theme.palette.text.secondary,
  };

  // The nodes and links of the shared graph component, built as it builds any other graph of the platform
  const graphData = useMemo(() => {
    const toParse = (n: ProofGraphNode) => ({
      id: n.id,
      entity_type: n.entity_type,
      parent_types: ['Stix-Core-Object'],
      relationship_type: '',
      is_inferred: false,
      name: n.name,
      representative: { main: n.name },
      objectMarking: [],
    }) as unknown as ObjectToParse;
    const nodes: GraphNode[] = graph.nodes.map((n) => {
      const node = buildNode(toParse(n), {});
      return {
        ...node,
        color: ROLE_COLORS[n.kind],
        label: n.score ? `${node.label} · ${n.score}` : node.label,
        disabled: n.status === 'proposed', // proposed: drawn faded
      };
    });
    const links: GraphLink[] = graph.links.map((l) => {
      const link = buildLink({
        id: l.id,
        entity_type: l.relationship_type,
        relationship_type: l.relationship_type,
        parent_types: ['basic-relationship', 'stix-core-relationship'],
        is_inferred: false,
        from: { id: l.source },
        to: { id: l.target },
        objectMarking: [],
      } as unknown as ObjectToParse);
      return l.relationship_type === KEYWORD_RELATIONSHIP ? { ...link, label: t_i18n('mentions') } : link;
    });
    return { nodes, links };
  }, [graph, theme]);

  const typeOptions = Array.from(new Set(matches.map((m) => m.match_entity_type))).sort().map((type) => ({ value: type, label: t_i18n(`entity_${type}`) }));
  const criterionOptions = criteria.map((c) => ({ value: c.id, label: c.name }));
  const scoreOptions = [0, ...thresholds].map((s) => ({ value: String(s), label: s === 0 ? t_i18n('Any score') : `${t_i18n('Score')} ≥ ${s}` }));

  const legend = [
    { color: ROLE_COLORS.anchor, label: t_i18n('Subject: where the proof starts'), faded: false },
    { color: ROLE_COLORS.entity, label: t_i18n('Entity of the requirement'), faded: false },
    ...(includeProposed ? [{ color: theme.palette.text.secondary, label: t_i18n('Proposed, not in the requirement yet'), faded: true }] : []),
    ...(counts.texts > 0 ? [{ color: ROLE_COLORS.container, label: t_i18n('Container or keyword that mentions it'), faded: false }] : []),
  ];

  // The graph told in sentences
  const summary = [
    `${t_i18n('{subjects, plural, one {# subject brings in} other {# subjects bring in}} {entities, plural, one {# entity of the requirement} other {# entities of the requirement}}', { values: { subjects: counts.subjects, entities: counts.entities } })}${
      counts.texts > 0 ? ` (${t_i18n('{count, plural, one {and # container or keyword} other {and # containers or keywords}}', { values: { count: counts.texts } })})` : ''}.`,
    ...(graph.total > counts.entities ? [t_i18n('Only the best scores are shown: {shown} out of {total}.', { values: { shown: counts.entities, total: graph.total } })] : []),
    shared.length > 0
      ? t_i18n('{count, plural, one {# entity is brought in by several subjects: it is listed below.} other {# entities are brought in by several subjects: they are listed below.}}', { values: { count: shared.length } })
      : t_i18n('Each entity is brought in by a single subject.'),
  ];

  const openNode = (nodeId: string) => {
    const node = graph.nodes.find((n) => n.id === nodeId);
    if (!node || node.kind === 'keyword') return;
    if (node.matchId) setSelected(node.matchId);
    else navigate(`/dashboard/id/${node.id}`);
  };

  return (
    <>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr 1fr', lg: '160px minmax(0, 1fr) minmax(0, 1fr) 130px auto' }, gap: 2, alignItems: 'end', mb: 2 }}>
        <IrSelect label={t_i18n('Score')} value={String(minScore)} options={scoreOptions} onChange={(v) => setMinScore(Number(v))} />
        <IrMultiSelect label={t_i18n('Entity types')} values={types} options={typeOptions} onChange={setTypes} placeholder={t_i18n('All types')} />
        <IrMultiSelect label={t_i18n('Scope criteria')} values={criterionIds} options={criterionOptions} onChange={setCriterionIds} placeholder={t_i18n('All criteria')} />
        <IrSelect label={t_i18n('Entities shown')} value={String(limit)} options={LIMITS.map((l) => ({ value: String(l), label: `${t_i18n('Top')} ${l}` }))} onChange={(v) => setLimit(Number(v))} />
        <Box sx={{ pb: 1 }}>
          <Checkbox label={t_i18n('Include proposals')} checked={includeProposed} onCheckedChange={(checked) => setIncludeProposed(checked === true)} />
        </Box>
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', lg: 'minmax(0, 1fr) 300px' }, gap: 2 }}>
        <Paper padding={0}>
          <Box ref={parentRef} sx={{ height: 640, position: 'relative', overflow: 'hidden' }}>
            {graph.nodes.length === 0 ? (
              <Box sx={{ p: 3 }}><Text as="span" variant="content-base">{t_i18n('No entity matches these filters.')}</Text></Box>
            ) : (
              <>
                <Box sx={{ position: 'absolute', top: 12, left: 12, zIndex: 1, bgcolor: 'background.paper', border: '1px solid', borderColor: 'divider', borderRadius: 1, px: 1.5, py: 1, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                  {legend.map((item) => (
                    <Box key={item.label} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Box sx={{ width: 12, height: 12, borderRadius: '50%', border: '2px solid', borderColor: item.color, opacity: item.faded ? 0.4 : 1, flexShrink: 0 }} />
                      <Text as="span" variant="content-caption">{item.label}</Text>
                    </Box>
                  ))}
                  <Text as="span" variant="content-caption" style={{ opacity: 0.7, marginTop: 4 }}>{t_i18n('Arrow: the relationship that brought the entity in')}</Text>
                  <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('Zoom in to read the names, click an entity to see its proof')}</Text>
                </Box>
                <SimpleGraph2D
                  key={`${minScore}-${types.join()}-${criterionIds.join()}-${includeProposed}-${limit}`}
                  parentRef={parentRef}
                  graphData={graphData}
                  cooldownTicks={120}
                  onReady={(ref) => {
                    graphRef.current = ref;
                    ref.d3Force('charge')?.strength(-40);
                    ref.d3Force('link')?.distance(40);
                    ref.d3Force('gravity', gravity(0.06) as never);
                    ref.d3ReheatSimulation();
                  }}
                  onEngineStop={() => graphRef.current?.zoomToFit(400, 40)}
                  onNodeClick={(node) => openNode(node.id)}
                />
              </>
            )}
          </Box>
        </Paper>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Paper padding={16}>
            <Text as="div" variant="title-sm" style={{ marginBottom: 8 }}>{t_i18n('In short')}</Text>
            {summary.map((line) => <Text key={line} as="div" variant="content-compact" style={{ marginBottom: 6 }}>{line}</Text>)}
          </Paper>
          <Paper padding={16}>
            <Text as="div" variant="title-sm" style={{ marginBottom: 4 }}>{t_i18n('Brought in by several subjects')}</Text>
            <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginBottom: 8 }}>{t_i18n('The more subjects lead to an entity, the more widespread it is: ×3 = three subjects')}</Text>
            {shared.length === 0 && <Text as="span" variant="content-caption">{t_i18n('None among the entities shown.')}</Text>}
            {shared.slice(0, SHARED_SHOWN).map((n) => (
              <Box
                key={n.id}
                onClick={() => openNode(n.id)}
                sx={{ display: 'grid', gridTemplateColumns: '24px 1fr 34px 70px', gap: 1, alignItems: 'center', py: 0.5, cursor: 'pointer', borderBottom: '1px solid', borderColor: 'divider', '&:hover': { bgcolor: 'action.hover' } }}
              >
                <ItemIcon type={n.entity_type} size="small" />
                <Text as="span" variant="content-compact">{n.name}</Text>
                <Text as="span" variant="content-caption">{`×${n.sources}`}</Text>
                <ScoreBar score={n.score ?? 0} />
              </Box>
            ))}
          </Paper>
        </Box>
      </Box>
      <IrMatchDrawer
        irId={irId}
        match={(matches.find((m) => m.id === selected) ?? null) as IrMatchData | null}
        criteria={criteria}
        onClose={() => setSelected(null)}
        onChanged={() => startTransition(() => setFetchKey((k) => k + 1))}
      />
    </>
  );
};

export default IrGraph;
