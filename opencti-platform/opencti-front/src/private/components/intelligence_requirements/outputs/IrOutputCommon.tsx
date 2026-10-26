import React from 'react';
import { Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';

// Shared rendering helpers of the output screens (Overview, Entities, Inbox) of the proof of concept.

export interface IrCriterionRef {
  readonly id: string;
  readonly name: string;
  readonly kind: string;
  readonly mode?: string;
  readonly from_group_ids?: readonly string[];
  readonly from_in_requirement?: boolean;
}

export interface IrGroupRef {
  readonly id: string;
  readonly name: string;
}

export interface IrExplanationData {
  readonly criterion_id: string;
  readonly kind: string;
  readonly anchor_id?: string | null;
  readonly relationship_type?: string | null;
  readonly relationship?: {
    readonly confidence?: number | null;
    readonly created?: string | null;
    readonly start_time?: string | null;
    readonly createdBy?: { readonly name: string } | null;
  } | null;
  readonly direction?: string | null;
  readonly keyword?: string | null;
  readonly field?: string | null;
  readonly anchor?: { readonly representative: { readonly main: string } } | null;
  readonly container?: { readonly representative: { readonly main: string } } | null;
}

export const criterionName = (criteria: readonly IrCriterionRef[], id: string) => criteria.find((c) => c.id === id)?.name ?? id;

/**
 * One line of proof: why the entity entered the requirement.
 */
export const explanationText = (e: IrExplanationData) => {
  if (e.kind === 'graph') {
    const anchor = e.anchor?.representative.main ?? '?';
    return e.direction === 'incoming' ? `—${e.relationship_type}→ ${anchor}` : `${anchor} —${e.relationship_type}→`;
  }
  if (e.kind === 'keywords') {
    return `“${e.keyword}” in ${e.field} of ${e.container?.representative.main ?? 'itself'}`;
  }
  return 'matches the attribute filters';
};

/**
 * The same proof as a full sentence, with the entity itself: "Scattered Spider —uses→ Rhadamanthys".
 */
export const explanationSentence = (e: IrExplanationData, entityName: string) => {
  if (e.kind === 'graph' && entityName) {
    const anchor = e.anchor?.representative.main ?? '?';
    return e.direction === 'incoming' ? `${entityName} —${e.relationship_type}→ ${anchor}` : `${anchor} —${e.relationship_type}→ ${entityName}`;
  }
  return explanationText(e);
};

// A match reduced to what the proof chain needs (to walk back a second hop to its subject).
export interface IrChainMatch {
  readonly match_entity_id: string;
  readonly match_explanations: readonly IrExplanationData[];
}

export interface IrProofChain {
  nodes: string[]; // from the subject to the entity
  links: { relationship_type: string; incoming: boolean }[];
  groupIds: readonly string[]; // subject groups the chain starts from
  first: IrExplanationData; // the hop that reaches the subject (source, confidence, date)
}

/**
 * Rebuild the whole path of a graph proof, walking back second hops through the entities already in the requirement:
 * Black Basta —uses→ SystemBC —variant-of→ SystemBC v5.
 */
export const buildProofChain = (
  proof: IrExplanationData,
  entityName: string,
  criteria: readonly IrCriterionRef[],
  matches: readonly IrChainMatch[],
): IrProofChain => {
  const nodes = [entityName];
  const links: IrProofChain['links'] = [];
  let current = proof;
  let criterion = criteria.find((c) => c.id === current.criterion_id);
  for (let depth = 0; depth < 4; depth += 1) {
    nodes.unshift(current.anchor?.representative.main ?? '?');
    links.unshift({ relationship_type: current.relationship_type ?? '', incoming: current.direction === 'incoming' });
    if (!criterion?.from_in_requirement || !current.anchor_id) break;
    const anchorMatch = matches.find((m) => m.match_entity_id === current.anchor_id);
    const previous = anchorMatch?.match_explanations.find((e) => e.kind === 'graph');
    if (!previous) break;
    current = previous;
    criterion = criteria.find((c) => c.id === current.criterion_id);
  }
  return { nodes, links, groupIds: criterion?.from_group_ids ?? [], first: proof };
};

/**
 * The chain drawn with chips: the subject in blue, the entity in green, the hops in between neutral.
 */
export const ProofChain = ({ chain }: { chain: IrProofChain }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap' }}>
    {chain.nodes.map((node, i) => {
      const last = i === chain.nodes.length - 1;
      let severity: 'info' | 'low' | 'neutral' = 'neutral';
      if (i === 0) severity = 'info';
      else if (last) severity = 'low';
      return (
        <React.Fragment key={`${node}-${i}`}>
          <Chip label={node} severity={severity} />
          {!last && (
            <Text as="span" variant="content-caption" style={{ fontFamily: 'monospace', opacity: i === chain.links.length - 1 ? 1 : 0.6 }}>
              {chain.links[i].incoming ? `←${chain.links[i].relationship_type}—` : `—${chain.links[i].relationship_type}→`}
            </Text>
          )}
        </React.Fragment>
      );
    })}
  </Box>
);

export const STATUS_CHIP: Record<string, { label: string; severity: 'neutral' | 'info' | 'low' | 'medium' | 'high' | 'critical' }> = {
  auto: { label: 'Auto', severity: 'neutral' },
  accepted: { label: 'Accepted', severity: 'low' },
  proposed: { label: 'Proposed', severity: 'info' },
  rejected: { label: 'Rejected', severity: 'neutral' },
  removed: { label: 'Removed', severity: 'neutral' },
};

export const KIND_CHIP: Record<string, { label: string; severity: 'neutral' | 'info' | 'low' | 'medium' | 'high' | 'critical' }> = {
  proposed: { label: 'Proposed · to accept', severity: 'info' },
  entered: { label: 'Entered · for information', severity: 'neutral' },
  score: { label: 'Score threshold', severity: 'high' },
  health: { label: 'Requirement health', severity: 'medium' },
  brief: { label: 'AI brief', severity: 'info' },
};

export const StatusChip = ({ status, excluded, t }: { status: string; excluded?: boolean; t: (s: string) => string }) => {
  if (excluded) return <Chip label={t('Excluded')} severity="critical" size="sm" />;
  const chip = STATUS_CHIP[status] ?? STATUS_CHIP.auto;
  return <Chip label={t(chip.label)} severity={chip.severity} size="sm" />;
};

export const ScoreBar = ({ score, excluded }: { score: number; excluded?: boolean }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
    <Box sx={{ width: 70, height: 6, borderRadius: 3, bgcolor: 'action.hover', overflow: 'hidden' }}>
      <Box sx={{ width: `${excluded ? 0 : score}%`, height: '100%', background: 'linear-gradient(90deg, #42caff, #00f0bc)' }} />
    </Box>
    <Box component="span" sx={{ fontWeight: 600, fontSize: 13, minWidth: 26 }}>{excluded ? '—' : score}</Box>
  </Box>
);

export const IN_STATUSES = ['auto', 'accepted'];
