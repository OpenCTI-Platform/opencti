import React from 'react';
import { Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { CheckCircleOutlined, HighlightOffOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { irRelationshipLabel } from '../configuration/irConstants';

type Translate = (key: string, values?: { values: Record<string, unknown> }) => string;

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
export const explanationText = (t_i18n: Translate, e: IrExplanationData) => {
  if (e.kind === 'graph') {
    const anchor = e.anchor?.representative.main ?? '?';
    const rel = irRelationshipLabel(t_i18n, e.relationship_type ?? '');
    return e.direction === 'incoming' ? `—${rel}→ ${anchor}` : `${anchor} —${rel}→`;
  }
  if (e.kind === 'keywords') {
    const field = t_i18n(e.field ?? '');
    return e.container
      ? t_i18n('“{keyword}” in the {field} of {container}', { values: { keyword: e.keyword ?? '', field, container: e.container.representative.main } })
      : t_i18n('“{keyword}” in its {field}', { values: { keyword: e.keyword ?? '', field } });
  }
  return t_i18n('Matches the attribute filters');
};

/**
 * The same proof as a full sentence, with the entity itself: "Scattered Spider —uses→ Rhadamanthys".
 */
export const explanationSentence = (t_i18n: Translate, e: IrExplanationData, entityName: string) => {
  if (e.kind === 'graph' && entityName) {
    const anchor = e.anchor?.representative.main ?? '?';
    const rel = irRelationshipLabel(t_i18n, e.relationship_type ?? '');
    return e.direction === 'incoming' ? `${entityName} —${rel}→ ${anchor}` : `${anchor} —${rel}→ ${entityName}`;
  }
  return explanationText(t_i18n, e);
};

// The title of an inbox item, written from its kind and data in the reader's language (the stored title is the fallback)
export const itemTitleText = (
  t_i18n: Translate,
  item: {
    readonly item_kind: string;
    readonly item_title: string;
    readonly item_data: { readonly criterion_id?: string | null; readonly threshold?: number | null; readonly to_score?: number | null; readonly message?: string | null };
    readonly match?: { readonly entity?: { readonly representative: { readonly main: string } } | null } | null;
  },
) => {
  const name = item.match?.entity?.representative.main;
  if (!name) return item.item_title;
  if (item.item_kind === 'proposed') return t_i18n('{name} is proposed for the requirement', { values: { name } });
  if (item.item_kind === 'score') {
    // Older score items carry no threshold: the score reached is the next best fact
    const threshold = item.item_data.threshold ?? item.item_data.to_score;
    if (threshold != null) return t_i18n('{name} reached a score of {threshold}', { values: { name, threshold } });
  }
  if (item.item_kind === 'entered') {
    return item.item_data.criterion_id
      ? t_i18n('{name} is now in the requirement', { values: { name } })
      : t_i18n('{name} brought new entities into the requirement', { values: { name } });
  }
  return item.item_title;
};

// The trigger of a history point, stored in English by the engine, written in the reader's language.
// The known shapes are rebuilt from their parts (criterion name, relationship type, fields, user); anything else is shown as stored.
export const triggerText = (t_i18n: Translate, trigger: string | null | undefined): string => {
  if (!trigger) return '';
  let m = trigger.match(/^(Entered|New proof) through "(.*)"( \(second hop\))?$/);
  if (m) {
    const criterion = m[2];
    if (m[1] === 'Entered') return m[3] ? t_i18n('Entered through “{criterion}” (second hop)', { values: { criterion } }) : t_i18n('Entered through “{criterion}”', { values: { criterion } });
    return m[3] ? t_i18n('New proof through “{criterion}” (second hop)', { values: { criterion } }) : t_i18n('New proof through “{criterion}”', { values: { criterion } });
  }
  m = trigger.match(/^(New|Updated) (\S+) relationship$/);
  if (m) {
    const relationship = irRelationshipLabel(t_i18n, m[2]);
    return m[1] === 'New' ? t_i18n('New relationship: {relationship}', { values: { relationship } }) : t_i18n('Updated relationship: {relationship}', { values: { relationship } });
  }
  m = trigger.match(/^Updated: (.*)$/);
  if (m) return t_i18n('Updated: {fields}', { values: { fields: m[1] } });
  if (trigger === 'Entity created') return t_i18n('Entity created');
  if (trigger === 'Entity updated') return t_i18n('Entity updated');
  m = trigger.match(/^(Configuration changed|Accepted into the requirement|Accepted|Rejected|Removed from the requirement) by (.*)$/);
  if (m) {
    const user = m[2];
    if (m[1] === 'Configuration changed') return t_i18n('Configuration changed by {user}', { values: { user } });
    if (m[1] === 'Rejected') return t_i18n('Rejected by {user}', { values: { user } });
    if (m[1] === 'Removed from the requirement') return t_i18n('Removed from the requirement by {user}', { values: { user } });
    return t_i18n('Accepted by {user}', { values: { user } });
  }
  return trigger;
};

// The kind of a history point, as a label
export const historyKindLabel = (t_i18n: Translate, kind: string) => {
  if (kind === 'entry') return t_i18n('Entered');
  if (kind === 'fact') return t_i18n('New fact');
  if (kind === 'config') return t_i18n('Configuration');
  if (kind === 'decision') return t_i18n('Decision');
  return kind;
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
export const ProofChain = ({ chain }: { chain: IrProofChain }) => {
  const { t_i18n } = useFormatter();
  return (
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
                {chain.links[i].incoming
                  ? `←${irRelationshipLabel(t_i18n, chain.links[i].relationship_type)}—`
                  : `—${irRelationshipLabel(t_i18n, chain.links[i].relationship_type)}→`}
              </Text>
            )}
          </React.Fragment>
        );
      })}
    </Box>
  );
};

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
  if (excluded) return <Chip label={t('Not eligible')} severity="critical" size="sm" />;
  const chip = STATUS_CHIP[status] ?? STATUS_CHIP.auto;
  return <Chip label={t(chip.label)} severity={chip.severity} size="sm" />;
};

// The bar uses the primary token; an excluded entity reads "Not eligible" (the word of its status chip), never a dash.
// In a narrow column the number stays whole and the bar gives way (70 px at most, 24 px at least);
// an excluded entity has no score to draw, so its words take the whole cell
export const ScoreBar = ({ score, excluded }: { score: number; excluded?: boolean }) => {
  const { t_i18n } = useFormatter();
  if (excluded) {
    return <Box component="span" sx={{ fontWeight: 600, fontSize: 13 }}>{t_i18n('Not eligible')}</Box>;
  }
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
      <Box sx={{ flex: '0 1 70px', minWidth: 24, height: 6, borderRadius: 3, bgcolor: 'action.hover', overflow: 'hidden' }}>
        <Box sx={{ width: `${score}%`, height: '100%', bgcolor: 'primary.main' }} />
      </Box>
      <Box component="span" sx={{ flexShrink: 0, fontWeight: 600, fontSize: 13, minWidth: 26, whiteSpace: 'nowrap' }}>{score}</Box>
    </Box>
  );
};

// A met or unmet condition: the status icon of the platform in the success or error token, then its name
export const ConditionStatus = ({ met, name }: { met: boolean; name: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, color: met ? 'text.primary' : 'error.main' }}>
      {met
        ? <CheckCircleOutlined fontSize="small" color="success" titleAccess={t_i18n('Met')} />
        : <HighlightOffOutlined fontSize="small" color="error" titleAccess={t_i18n('Not met')} />}
      <Text as="span" variant="content-compact">{name}</Text>
    </Box>
  );
};

export const IN_STATUSES = ['auto', 'accepted'];
