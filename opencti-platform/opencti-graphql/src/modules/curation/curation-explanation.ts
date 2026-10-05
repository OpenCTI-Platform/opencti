import {
  ACTION_ACKNOWLEDGE,
  ACTION_ADD_ALIASES,
  ACTION_FIX_DATES,
  ACTION_MERGE,
  ACTION_PRESERVE_PROCEDURE,
  ACTION_RESOLVE_ATTRIBUTION,
  ACTION_REVOKE,
  ACTION_SET_FIELD,
  ACTION_UNMERGE,
  ACTION_UNREVOKE_INDICATOR,
  type BasicStoreEntityCurationProposal,
  type CurationEvidence,
  EVIDENCE_CANONICAL_COLLISION,
  EVIDENCE_DECAYED_INDICATOR,
  EVIDENCE_SHARED_ALIAS,
  EVIDENCE_TAXONOMY,
  EVIDENCE_TRIGRAM,
  RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY,
  RELATIONSHIP_CONFLICT_MODE_NOTE,
} from './curation-types';

/**
 * The explanation of a curation proposal: what will change, the evidence behind it, why in plain language, what the
 * confidence means and what each decision does. It is built here once and read by every consumer: the user interface
 * translates each message from its template and values, API clients and agents read the rendered English text.
 *
 * Message templates are user interface translation keys: placeholders only (no plural forms, no apostrophes), and value
 * names follow the conventions the user interface formats - a name ending in "Type" is an entity type, a name ending in
 * "Field" (or "field") is an attribute, an ISO date-time is a date.
 */

export interface ExplanationMessage {
  template: string;
  values: Record<string, string | number>;
  text: string;
}

export interface ExplanationEntity {
  id: string;
  name: string;
  entity_type: string;
}

export interface ExplanationSource {
  name: string;
  reference: string | null;
  url: string | null;
}

export interface ExplanationChange {
  field: ExplanationMessage;
  before: string[];
  after: string[];
}

export interface ExplanationEvidence {
  message: ExplanationMessage;
  entities: ExplanationEntity[];
  sources: ExplanationSource[];
}

export type ExplanationConfidenceLevel = 'high' | 'medium' | 'low';

export interface ProposalExplanation {
  title: ExplanationMessage;
  changes: ExplanationChange[];
  evidence: ExplanationEvidence[];
  why: ExplanationMessage;
  confidence: { score: number; level: ExplanationConfidenceLevel; meaning: ExplanationMessage };
  on_accept: ExplanationMessage;
  on_reject: ExplanationMessage;
  on_later: ExplanationMessage;
  reversible: boolean;
  text: string;
}

export interface ExplanationSubject {
  internal_id: string;
  entity_type: string;
  name?: string | null;
  aliases?: string[] | null;
  x_opencti_aliases?: string[] | null;
}

export interface ExplanationOptions {
  mergeRetentionDays?: number;
  relationshipConflictMode?: string;
  catalogueVersion?: string;
}

export type ExplainedProposal = Pick<BasicStoreEntityCurationProposal,
  'proposal_kind' | 'recommended_action' | 'action_payload' | 'curation_evidence' | 'confidence_score' | 'in_ambiguous_band'
  | 'subject_ids' | 'subject_types' | 'subject_names' | 'target_id'>;

// region rendering
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
const FIELD_LABELS: Record<string, string> = {
  first_seen: 'First seen',
  last_seen: 'Last seen',
  valid_from: 'Valid from',
  valid_until: 'Valid until',
  start_time: 'Start time',
  stop_time: 'Stop time',
};

const formatDateTime = (value: string) => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const iso = date.toISOString();
  return iso.endsWith('T00:00:00.000Z') ? iso.slice(0, 10) : `${iso.slice(0, 16).replace('T', ' ')} UTC`;
};

/** How a value reads in the English text, following the value name conventions of the templates. */
const renderValue = (key: string, value: string | number) => {
  if (typeof value === 'number') return String(value);
  if (key.endsWith('Type')) return value.replace(/-/g, ' ');
  if (key === 'field' || key.endsWith('Field')) return FIELD_LABELS[value] ?? value.replace(/_/g, ' ');
  if (DATE_TIME.test(value)) return formatDateTime(value);
  return value;
};

export const renderTemplate = (template: string, values: Record<string, string | number>) => {
  return template.replace(/\{(\w+)\}/g, (match, key: string) => (values[key] === undefined ? match : renderValue(key, values[key])));
};

const message = (template: string, values: Record<string, string | number> = {}): ExplanationMessage => ({
  template,
  values,
  text: renderTemplate(template, values),
});

const formatValue = (value: unknown): string => {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'string') return DATE_TIME.test(value) ? formatDateTime(value) : value;
  if (Array.isArray(value)) return value.map(formatValue).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

const listOf = (names: string[]) => names.join(', ');
const quotedList = (names: string[]) => names.map((name) => `"${name}"`).join(', ');
// endregion

// region inputs
const parseObject = (value: unknown): Record<string, any> => {
  let parsed = value;
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value);
    } catch {
      return {};
    }
  }
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, any> : {};
};

const detailsOf = (item: CurationEvidence) => parseObject(item.details);
const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0) : []);
const sameName = (left: string, right: string) => left.trim().toLowerCase() === right.trim().toLowerCase();
const withoutNames = (names: string[], excluded: string[]) => names.filter((name) => !excluded.some((other) => sameName(name, other)));
const uniqueNames = (names: string[]) => names.filter((name, index) => names.findIndex((other) => sameName(other, name)) === index);

interface Subject extends ExplanationEntity {
  aliases: string[];
}

const subjectsOf = (proposal: ExplainedProposal, loaded: ExplanationSubject[]): Subject[] => {
  const byId = new Map(loaded.map((subject) => [subject.internal_id, subject]));
  return proposal.subject_ids.map((id, index) => {
    const subject = byId.get(id);
    return {
      id,
      entity_type: subject?.entity_type ?? proposal.subject_types?.[index] ?? '',
      name: subject?.name ?? proposal.subject_names?.[index] ?? id,
      aliases: strings(subject?.aliases ?? subject?.x_opencti_aliases ?? []),
    };
  });
};

const entityOf = ({ id, name, entity_type }: Subject): ExplanationEntity => ({ id, name, entity_type });
// endregion

// region evidence
const CATALOGUE_URLS: Record<string, string> = {
  'misp-threat-actor': 'https://github.com/MISP/misp-galaxy/blob/main/clusters/threat-actor.json',
  'misp-malpedia': 'https://github.com/MISP/misp-galaxy/blob/main/clusters/malpedia.json',
};
const MITRE_PATHS: Record<string, string> = { G: 'groups', S: 'software', C: 'campaigns' };

/** The public catalogue entry a taxonomy evidence cites, with a link a reader can open. */
export const catalogueSource = (source: string, cluster: string): ExplanationSource => {
  const reference = cluster.includes(':') ? cluster.slice(cluster.indexOf(':') + 1) : cluster;
  if (source === 'mitre') {
    const path = MITRE_PATHS[reference.charAt(0).toUpperCase()];
    return { name: 'MITRE ATT&CK', reference, url: path ? `https://attack.mitre.org/${path}/${reference}/` : 'https://attack.mitre.org/' };
  }
  const name = source === 'misp-malpedia' ? 'MISP galaxy (Malpedia)' : 'MISP galaxy (threat actors)';
  return { name, reference, url: CATALOGUE_URLS[source] ?? 'https://github.com/MISP/misp-galaxy' };
};

/** The sentence of an evidence item, from the parameters its detector recorded; the stored description otherwise. */
export const evidenceMessage = (item: CurationEvidence): ExplanationMessage => {
  const details = detailsOf(item);
  const text = (key: string) => (typeof details[key] === 'string' && details[key].length > 0 ? details[key] as string : null);
  const count = (key: string) => (typeof details[key] === 'number' ? details[key] as number : null);
  const percent = (value: number | null) => (value === null ? null : Math.round(value * 100));
  const left = text('left_name');
  const right = text('right_name');
  const canonical = text('canonical');
  const clusterRef = text('cluster');
  const mitre = text('source') === 'mitre';
  // The catalogue reference a reader can look up (G0007), without the internal source prefix.
  const cluster = clusterRef ? catalogueSource(text('source') ?? '', clusterRef).reference : null;
  const sharedIds = Array.isArray(details.shared_ids) ? details.shared_ids : null;
  const shared = count('shared_count') ?? (sharedIds && sharedIds.length < 50 ? sharedIds.length : null);
  const overlap = percent(item.score);
  switch (item.evidence_type) {
    case EVIDENCE_CANONICAL_COLLISION:
    case EVIDENCE_SHARED_ALIAS:
    case 'type_collision': {
      if (!left || !right) break;
      if (cluster) {
        return mitre
          ? message('"{left}" and "{right}" are listed as names of the same object by MITRE ATT&CK ({cluster})', { left, right, cluster })
          : message('"{left}" and "{right}" are listed as names of the same object by the MISP galaxy ({cluster})', { left, right, cluster });
      }
      if (!canonical) break;
      const leftType = text('left_type');
      const rightType = text('right_type');
      if (item.evidence_type === 'type_collision' && leftType && rightType) {
        return message('"{left}" ({leftType}) and "{right}" ({rightType}) normalize to the same name "{canonical}" but have different types', { left, right, canonical, leftType, rightType });
      }
      return details.stripped === true
        ? message('"{left}" and "{right}" are the same name once vendor suffixes and qualifiers are removed ("{canonical}")', { left, right, canonical })
        : message('"{left}" and "{right}" normalize to the same name "{canonical}" (case, punctuation, separators, digits used as letters)', { left, right, canonical });
    }
    case EVIDENCE_TAXONOMY: {
      if (!cluster) break;
      if (left && right) {
        return mitre
          ? message('"{left}" and "{right}" are listed as names of the same object by MITRE ATT&CK ({cluster})', { left, right, cluster })
          : message('"{left}" and "{right}" are listed as names of the same object by the MISP galaxy ({cluster})', { left, right, cluster });
      }
      const aliases = strings(details.aliases);
      const matched = text('matched_name') ?? text('entity_name');
      if (aliases.length === 0 || !matched) break;
      const values = { count: aliases.length, matched, names: listOf(aliases), reference: cluster };
      if (mitre) {
        return aliases.length === 1
          ? message('MITRE ATT&CK lists 1 of these names under {reference} ("{matched}"): {names}', values)
          : message('MITRE ATT&CK lists {count} of these names under {reference} ("{matched}"): {names}', values);
      }
      return aliases.length === 1
        ? message('The MISP galaxy lists 1 of these names for "{matched}": {names}', values)
        : message('The MISP galaxy lists {count} of these names for "{matched}": {names}', values);
    }
    case EVIDENCE_TRIGRAM: {
      const similarity = percent(count('similarity'));
      if (!left || !right || similarity === null) break;
      return message('"{left}" and "{right}" are {similarity}% similar (trigram similarity)', { left, right, similarity });
    }
    case 'description_similarity': {
      const similarity = percent(count('similarity'));
      const terms = strings(details.shared_terms);
      if (similarity === null || terms.length === 0) break;
      return message('The descriptions are {similarity}% similar (shared terms: {terms})', { similarity, terms: listOf(terms) });
    }
    case 'attack_overlap': {
      const leftCount = count('left_count');
      const rightCount = count('right_count');
      if (shared === null || leftCount === null || rightCount === null || overlap === null) break;
      return message('{shared} ATT&CK techniques in common ({overlap}% overlap of {left} and {right})', { shared, overlap, left: leftCount, right: rightCount });
    }
    case 'shared_tools':
      if (shared === null || overlap === null) break;
      return message('{count} tools or malware in common ({overlap}% overlap)', { count: shared, overlap });
    case 'shared_infrastructure':
      if (shared === null || overlap === null) break;
      return message('{count} infrastructure elements in common ({overlap}% overlap)', { count: shared, overlap });
    case 'victimology':
      if (shared === null || overlap === null) break;
      return message('{count} targeted sectors, locations or organizations in common ({overlap}% overlap)', { count: shared, overlap });
    case 'co_attribution':
      if (shared === null) break;
      return message('{count} campaign(s) or incident(s) attributed to both', { count: shared });
    case 'graph_similarity':
      if (overlap === null) break;
      return message('Structural similarity of {similarity}% in the knowledge graph analytics', { similarity: overlap });
    case 'source_agreement':
      if (Array.isArray(details.shared_sources)) return message('The same source maintains both entities separately, which suggests they are distinct');
      if (Array.isArray(details.left_sources)) return message('The entities come from different sources, a typical pattern of vendor naming');
      break;
    case 'date_inversion': {
      const startField = text('start_field');
      const stopField = text('stop_field');
      const start = text('start');
      const stop = text('stop');
      if (!startField || !stopField || !start || !stop) break;
      return message('{startField} ({start}) is after {stopField} ({stop})', { startField, start, stopField, stop });
    }
    case 'attribution_conflict': {
      const attributed = text('attributed_name');
      const actors = strings(details.actor_names);
      if (!attributed || actors.length === 0) break;
      return message('"{attributed}" is attributed to {actors}, actors that were decided to be distinct, and no source attributes it to all of them', { attributed, actors: quotedList(actors) });
    }
    case 'revoked_indicator': {
      const name = text('indicator_name');
      const observables = Array.isArray(details.observables) ? details.observables : null;
      if (!name || !observables) break;
      return message('Indicator "{name}" is revoked while {count} observable(s) it is based on are still active', { name, count: observables.length });
    }
    case 'merged_entity': {
      const name = text('entity_name');
      const sources = strings(details.source_names);
      if (!name || sources.length === 0) break;
      return message('"{name}" results from a merge with {sources} and is now involved in a contradiction', { name, sources: quotedList(sources) });
    }
    case 'staleness': {
      const date = text('last_activity');
      const months = count('months');
      if (!date || months === null) break;
      return message('No update and no new relationship since {date} (more than {months} months)', { date, months });
    }
    case EVIDENCE_DECAYED_INDICATOR: {
      const score = count('score');
      const revokeScore = count('revoke_score');
      if (score === null || revokeScore === null) break;
      return message('The decayed score ({score}) is at or below the revoke score ({revokeScore}) but the indicator is still active', { score, revokeScore });
    }
    case 'procedure_conflict': {
      const from = text('from_name');
      const to = text('to_name');
      if (!from || !to) break;
      return message('The procedure of "{from} uses {to}" was replaced by a different procedure from another source', { from, to });
    }
    case 'field_conflict': {
      const field = text('field');
      if (!field) break;
      return message('"{field}" was overwritten by a less authoritative source according to the field authority rules', { field });
    }
    default:
      break;
  }
  return message('{description}', { description: item.description });
};

const evidenceOf = (items: CurationEvidence[], entities: ExplanationEntity[]): ExplanationEvidence[] => items.map((item) => {
  const details = detailsOf(item);
  const cluster = typeof details.cluster === 'string' ? details.cluster : null;
  return {
    message: evidenceMessage(item),
    entities,
    sources: item.evidence_type === EVIDENCE_TAXONOMY && cluster ? [catalogueSource(String(details.source ?? ''), cluster)] : [],
  };
});
// endregion

// region confidence
/** The confidence in words: the ambiguous band is where a person decides, above it the evidence is conclusive. */
export const confidenceLevel = (proposal: Pick<ExplainedProposal, 'confidence_score' | 'in_ambiguous_band'>): ExplanationConfidenceLevel => {
  if (proposal.in_ambiguous_band) return 'medium';
  return proposal.confidence_score >= 0.7 ? 'high' : 'low';
};

const confidenceOf = (proposal: ExplainedProposal) => {
  const score = Number.isFinite(proposal.confidence_score) ? proposal.confidence_score : 0;
  const level = confidenceLevel({ confidence_score: score, in_ambiguous_band: proposal.in_ambiguous_band });
  const values = { percent: Math.round(score * 100) };
  const meanings: Record<ExplanationConfidenceLevel, ExplanationMessage> = {
    high: message('High ({percent}%): the evidence is strong and consistent.', values),
    medium: message('Medium ({percent}%): the evidence points this way but is not conclusive, so a person should decide.', values),
    low: message('Low ({percent}%): the evidence is weak. Check it before accepting.', values),
  };
  return { score, level, meaning: meanings[level] };
};
// endregion

// region proposal kinds
interface KindExplanation {
  title: ExplanationMessage;
  changes: ExplanationChange[];
  evidence: ExplanationEvidence[];
  why: ExplanationMessage;
  on_accept: ExplanationMessage;
  on_reject: ExplanationMessage;
  reversible: boolean;
}

const SPELLING_EVIDENCE = [EVIDENCE_CANONICAL_COLLISION, EVIDENCE_SHARED_ALIAS, EVIDENCE_TRIGRAM];
const DEFAULT_RETENTION_DAYS = 365;

const explainAddAliases = (proposal: ExplainedProposal, subjects: Subject[], options: ExplanationOptions): KindExplanation => {
  const payload = parseObject(proposal.action_payload);
  const target = subjects.find((subject) => subject.id === (proposal.target_id ?? proposal.subject_ids[0])) ?? subjects[0];
  const { name } = target;
  const current = target.aliases;
  const added = withoutNames(uniqueNames(strings(payload.aliases)), [name, ...current]);
  const values = { name, count: added.length };
  let title = message('Add {count} aliases to {name}', values);
  if (added.length === 1) title = message('Add 1 alias to {name}', values);
  if (added.length === 0) title = message('No alias left to add to {name}', values);
  const items = proposal.curation_evidence ?? [];
  // The catalogue entries justify the names, not another entity: the evidence links to them.
  const evidence = evidenceOf(items, []);
  const catalogueLists = items.filter((item) => item.evidence_type === EVIDENCE_TAXONOMY).map((item) => strings(detailsOf(item).aliases));
  if (catalogueLists.length > 1) {
    const everywhere = added.filter((alias) => catalogueLists.every((list) => list.some((listed) => sameName(listed, alias))));
    if (everywhere.length > 0) {
      const values = { total: catalogueLists.length, names: listOf(everywhere) };
      evidence.push({
        message: catalogueLists.length === 2 ? message('Listed by both catalogues: {names}', values) : message('Listed by all {total} catalogues: {names}', values),
        entities: [],
        sources: [],
      });
    }
  }
  evidence.push({ message: message('No other entity in this platform carries any of these names.'), entities: [], sources: [] });
  return {
    title,
    changes: [{ field: message('Aliases'), before: current, after: [...current, ...added] }],
    evidence,
    why: message(
      'Security vendors give {name} different names. These names come from the public catalogues of threat names shipped with OpenCTI (copy of {catalogueDate}), cited in the evidence: they were not read from your data or from another OpenCTI platform. As aliases, they let search, imports and duplicate detection recognize {name} under each of them.',
      { name, catalogueDate: options.catalogueVersion ?? '-' },
    ),
    on_accept: message('The names are added to the aliases of {name}. Nothing else changes. You can undo it later with Revert on this proposal.', values),
    on_reject: message('Nothing changes. The same names are not proposed again for {name}.', values),
    reversible: true,
  };
};

const explainMerge = (proposal: ExplainedProposal, subjects: Subject[], options: ExplanationOptions): KindExplanation => {
  const target = subjects.find((subject) => subject.id === proposal.target_id) ?? subjects[0];
  const others = subjects.filter((subject) => subject.id !== target.id);
  const gained = withoutNames(uniqueNames(others.flatMap((other) => [other.name, ...other.aliases])), [target.name, ...target.aliases]);
  const values = { target: target.name, other: others[0]?.name ?? '-', count: others.length, days: options.mergeRetentionDays ?? DEFAULT_RETENTION_DAYS };
  const items = proposal.curation_evidence ?? [];
  const spelledAlike = items.some((item) => SPELLING_EVIDENCE.includes(item.evidence_type));
  const catalogued = items.some((item) => item.evidence_type === EVIDENCE_TAXONOMY);
  const whyValues = { left: target.name, right: others[0]?.name ?? '-', entityType: target.entity_type };
  let why = message('"{left}" and "{right}" share their techniques, tools or targets so closely that they may describe the same thing, although their names differ. Check the evidence before merging.', whyValues);
  if (catalogued) {
    why = message('"{left}" and "{right}" are listed as two names of the same {entityType} by a public catalogue of threat names shipped with OpenCTI, so they very likely describe the same thing. Two copies split its reports, indicators and relationships between them.', whyValues);
  }
  if (spelledAlike) {
    why = message('The {entityType} entities "{left}" and "{right}" carry the same name written differently, so they very likely describe the same thing. Two copies split its reports, indicators and relationships between them.', whyValues);
  }
  return {
    title: others.length === 1 ? message('Merge "{other}" into "{target}"', values) : message('Merge {count} entities into "{target}"', values),
    changes: [
      { field: message('Entities'), before: subjects.map((subject) => subject.name), after: [target.name] },
      { field: message('Aliases of {target}', values), before: target.aliases, after: [...target.aliases, ...gained] },
    ],
    evidence: evidenceOf(items, subjects.map(entityOf)),
    why,
    on_accept: message('The other entities are merged into "{target}": their names become aliases of "{target}", and their relationships, reports and external references move to it. The merge is recorded and can be undone for {days} days from Data > Curation > Merges.', values),
    on_reject: message('Nothing changes. These entities are not proposed for a merge again.'),
    reversible: true,
  };
};

const explainTypeMismatch = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => {
  const [left, right] = subjects;
  const values = { left: left?.name ?? '-', leftType: left?.entity_type ?? '-', right: right?.name ?? '-', rightType: right?.entity_type ?? '-' };
  return {
    title: message('Check the type of "{left}" ({leftType}) and "{right}" ({rightType})', values),
    changes: [],
    evidence: evidenceOf(proposal.curation_evidence ?? [], subjects.map(entityOf)),
    why: message('Two entities of different types carry the same name. One of them is probably typed wrongly: if they are the same object, change the type of one of them, then merge them.'),
    on_accept: message('Nothing changes in the knowledge: the proposal is closed as reviewed and is not raised again.'),
    on_reject: message('Nothing changes. The proposal is closed and is not raised again.'),
    reversible: true,
  };
};

const explainFixDates = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => {
  const payload = parseObject(proposal.action_payload);
  const [subject] = subjects;
  const startField = String(payload.start_field ?? '');
  const stopField = String(payload.stop_field ?? '');
  const start = formatValue(payload.start);
  const stop = formatValue(payload.stop);
  const values = { name: subject?.name ?? '-', startField, stopField };
  return {
    title: message('Swap the {startField} and {stopField} dates of "{name}"', values),
    changes: [
      { field: message('{field}', { field: startField }), before: [start], after: [stop] },
      { field: message('{field}', { field: stopField }), before: [stop], after: [start] },
    ],
    evidence: evidenceOf(proposal.curation_evidence ?? [], subjects.map(entityOf)),
    why: message('The date that marks the start comes after the date that marks the end, which cannot be: the two dates were most likely entered the wrong way round.'),
    on_accept: message('The two dates are swapped. This cannot be undone from the proposal: edit the dates of "{name}" to change them back.', values),
    on_reject: message('Nothing changes. This inversion is not proposed again.'),
    reversible: false,
  };
};

const explainResolveAttribution = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => {
  const payload = parseObject(proposal.action_payload);
  const actorIds = new Set((Array.isArray(payload.relationships) ? payload.relationships : []).map((relation: { actor_id?: string }) => relation.actor_id));
  const attributed = subjects.find((subject) => subject.id === (payload.attributed_id ?? proposal.target_id)) ?? subjects[0];
  const actors = subjects.filter((subject) => actorIds.has(subject.id));
  const values = { attributed: attributed?.name ?? '-' };
  return {
    title: message('Keep one attribution of "{attributed}"', values),
    changes: [{ field: message('Attributed to'), before: actors.map((actor) => actor.name), after: [] }],
    evidence: evidenceOf(proposal.curation_evidence ?? [], subjects.map(entityOf)),
    why: message('"{attributed}" is attributed to several actors that were decided to be distinct entities, and no single source attributes it to all of them. At most one of these attributions is right.', values),
    on_accept: message('Only the attribution you choose is kept; the attributions to the other actors are deleted. You can undo it later with Revert on this proposal: the deleted attributions are restored.'),
    on_reject: message('Nothing changes. Every attribution stays, and this conflict is not proposed again.'),
    reversible: true,
  };
};

const explainUnrevoke = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => {
  const [indicator, ...observables] = subjects;
  const values = { name: indicator?.name ?? '-' };
  return {
    title: message('Reactivate the indicator "{name}"', values),
    changes: [{ field: message('Revoked'), before: ['Yes'], after: ['No'] }],
    evidence: evidenceOf(proposal.curation_evidence ?? [], observables.map(entityOf)),
    why: message('The indicator "{name}" was revoked, but observables it detects were seen active since then (updated with a score of 50 or more). While it stays revoked, it no longer detects them.', values),
    on_accept: message('The indicator is reactivated for its original lifetime. You can undo it later with Revert on this proposal.'),
    on_reject: message('Nothing changes. The indicator stays revoked and this case is not proposed again.'),
    reversible: true,
  };
};

const explainUnmerge = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => {
  const [subject] = subjects;
  const merged = proposal.curation_evidence?.find((item) => item.evidence_type === 'merged_entity');
  const sources = merged ? strings(detailsOf(merged).source_names) : [];
  const values = { name: subject?.name ?? '-' };
  return {
    title: message('Undo the merge of "{name}"', values),
    changes: [{ field: message('Entities'), before: [values.name], after: [values.name, ...sources] }],
    evidence: evidenceOf(proposal.curation_evidence ?? [], subjects.map(entityOf)),
    why: message('"{name}" was produced by merging several entities and is now involved in a contradiction: the merge may have joined entities that are actually different.', values),
    on_accept: message('The merge is undone: the merged entities are restored from their snapshots, with their relationships. This cannot be undone from the proposal; merge them again if needed.'),
    on_reject: message('Nothing changes. The merged entity stays as it is.'),
    reversible: false,
  };
};

const explainRevoke = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => {
  const [subject] = subjects;
  const items = proposal.curation_evidence ?? [];
  const staleness = items.find((item) => item.evidence_type === 'staleness');
  const months = staleness ? Number(detailsOf(staleness).months) : Number.NaN;
  const values = { name: subject?.name ?? '-', months: Number.isFinite(months) ? months : '-' };
  const decayed = items.some((item) => item.evidence_type === EVIDENCE_DECAYED_INDICATOR);
  return {
    title: message('Revoke "{name}"', values),
    changes: [{ field: message('Revoked'), before: ['No'], after: ['Yes'] }],
    evidence: evidenceOf(items, subjects.map(entityOf)),
    why: decayed && !staleness
      ? message('The score of the indicator "{name}" decayed down to its revoke score, but the indicator is still active.', values)
      : message('Nothing about "{name}" changed for more than {months} months: no update and no new relationship. Revoking it marks it as no longer current, without deleting it.', values),
    on_accept: message('"{name}" is marked as revoked; nothing is deleted. You can undo it later with Revert on this proposal.', values),
    on_reject: message('Nothing changes. "{name}" is not proposed again for this period of inactivity.', values),
    reversible: true,
  };
};

const explainPreserveProcedure = (proposal: ExplainedProposal, subjects: Subject[], options: ExplanationOptions): KindExplanation => {
  const payload = parseObject(proposal.action_payload);
  const item = proposal.curation_evidence?.find((entry) => entry.evidence_type === 'procedure_conflict');
  const details = item ? detailsOf(item) : {};
  const values = { from: String(details.from_name ?? '-'), to: String(details.to_name ?? '-') };
  const previous = formatValue(parseObject(payload.previous).text);
  const current = formatValue(parseObject(payload.current).text);
  const mode = options.relationshipConflictMode;
  let changes: ExplanationChange[] = [{ field: message('Procedures'), before: [current], after: [previous, current] }];
  let onAccept = message('The replaced procedure is kept next to the current one on the relationship. You can undo it later with Revert on this proposal.');
  if (mode === RELATIONSHIP_CONFLICT_MODE_NOTE) {
    changes = [{ field: message('Notes'), before: [], after: [previous] }];
    onAccept = message('The replaced procedure is kept in a note attached to the relationship. You can undo it later with Revert on this proposal: the note is deleted.');
  } else if (mode === RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY) {
    changes = [];
    onAccept = message('Nothing changes in the knowledge: the curation settings only report these conflicts. The proposal is closed as reviewed.');
  }
  return {
    title: message('Keep both procedures of "{from} uses {to}"', values),
    changes,
    evidence: evidenceOf(proposal.curation_evidence ?? [], subjects.map(entityOf)),
    why: message('Two sources describe differently how "{from}" uses "{to}", and the later description replaced the earlier one. Both may be right: keeping both avoids losing what the first source reported.', values),
    on_accept: onAccept,
    on_reject: message('Nothing changes. Only the current procedure stays.'),
    reversible: true,
  };
};

const explainSetField = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => {
  const payload = parseObject(proposal.action_payload);
  const [subject] = subjects;
  const field = String(payload.key ?? '');
  const values = { name: subject?.name ?? '-', field, entityType: subject?.entity_type ?? '-' };
  return {
    title: message('Restore the {field} of "{name}"', values),
    changes: [{ field: message('{field}', { field }), before: [formatValue(payload.overwritten_value)], after: [formatValue(payload.value)] }],
    evidence: evidenceOf(proposal.curation_evidence ?? [], subjects.map(entityOf)),
    why: message('The field authority rules say which source is trusted for this field ({field}, {entityType}): a less trusted source replaced the value written by a more trusted one.', values),
    on_accept: message('The value of the more trusted source is written back. You can undo it later with Revert on this proposal.'),
    on_reject: message('Nothing changes. The current value stays.'),
    reversible: true,
  };
};

const explainOther = (proposal: ExplainedProposal, subjects: Subject[]): KindExplanation => ({
  title: message('Review "{name}"', { name: subjects.map((subject) => subject.name).join(' / ') || '-' }),
  changes: [],
  evidence: evidenceOf(proposal.curation_evidence ?? [], subjects.map(entityOf)),
  why: message('The curation found something to review on these entities: read the evidence below.'),
  on_accept: message('The recommended change is applied.'),
  on_reject: message('Nothing changes.'),
  reversible: false,
});
// endregion

/** The whole explanation as plain text, for readers that do not render the structure (agents, notifications). */
export const explanationText = (explanation: Omit<ProposalExplanation, 'text'>) => {
  const lines = [explanation.title.text];
  if (explanation.changes.length > 0) {
    lines.push('What changes:');
    explanation.changes.forEach((change) => {
      lines.push(`- ${change.field.text}: ${change.before.length > 0 ? change.before.join(', ') : '(none)'} -> ${change.after.length > 0 ? change.after.join(', ') : '(to choose)'}`);
    });
  } else {
    lines.push('What changes: nothing in the knowledge.');
  }
  lines.push('Evidence:');
  explanation.evidence.forEach((item) => {
    const sources = item.sources.map((source) => [source.name, source.reference, source.url].filter(Boolean).join(' ')).join('; ');
    lines.push(`- ${item.message.text}${sources ? ` (source: ${sources})` : ''}`);
  });
  lines.push(`Why: ${explanation.why.text}`);
  lines.push(`Confidence: ${explanation.confidence.meaning.text}`);
  lines.push(`Accept: ${explanation.on_accept.text}`);
  lines.push(`Reject: ${explanation.on_reject.text}`);
  lines.push(`Later: ${explanation.on_later.text}`);
  return lines.join('\n');
};

export const buildProposalExplanation = (proposal: ExplainedProposal, loadedSubjects: ExplanationSubject[], options: ExplanationOptions = {}): ProposalExplanation => {
  const subjects = subjectsOf(proposal, loadedSubjects);
  let kind: KindExplanation;
  switch (proposal.recommended_action) {
    case ACTION_ADD_ALIASES:
      kind = explainAddAliases(proposal, subjects, options);
      break;
    case ACTION_MERGE:
      kind = explainMerge(proposal, subjects, options);
      break;
    case ACTION_ACKNOWLEDGE:
      kind = explainTypeMismatch(proposal, subjects);
      break;
    case ACTION_FIX_DATES:
      kind = explainFixDates(proposal, subjects);
      break;
    case ACTION_RESOLVE_ATTRIBUTION:
      kind = explainResolveAttribution(proposal, subjects);
      break;
    case ACTION_UNREVOKE_INDICATOR:
      kind = explainUnrevoke(proposal, subjects);
      break;
    case ACTION_UNMERGE:
      kind = explainUnmerge(proposal, subjects);
      break;
    case ACTION_REVOKE:
      kind = explainRevoke(proposal, subjects);
      break;
    case ACTION_PRESERVE_PROCEDURE:
      kind = explainPreserveProcedure(proposal, subjects, options);
      break;
    case ACTION_SET_FIELD:
      kind = explainSetField(proposal, subjects);
      break;
    default:
      kind = explainOther(proposal, subjects);
  }
  const explanation = {
    ...kind,
    confidence: confidenceOf(proposal),
    on_later: message('Nothing changes. The proposal stays open in Data > Curation until someone decides.'),
  };
  return { ...explanation, text: explanationText(explanation) };
};
