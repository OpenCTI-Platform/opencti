import { useTheme } from '@mui/styles';
import type { PayloadError } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';

export const CURATION_PROPOSAL_KINDS = ['merge', 'alias', 'split', 'contradiction', 'stale', 'relationship_conflict', 'type_mismatch', 'field_precedence'] as const;
export const CURATION_PROPOSAL_STATUSES = ['open', 'accepted', 'rejected', 'auto_applied', 'reverted'] as const;
export const CURATION_SOURCE_CLASSES = ['any', 'connector', 'manual'] as const;
export const CURATION_RELATIONSHIP_CONFLICT_MODES = ['procedures_array', 'note', 'detect_only'] as const;
export const CURATION_WEEK_DAYS = [0, 1, 2, 3, 4, 5, 6] as const;
export const CURATION_PROPOSALS_PATH = '/dashboard/data/curation/inbox';
export const CURATION_MERGES_PATH = '/dashboard/data/curation/merges';
export const CURATION_HEALTH_PATH = '/dashboard/data/curation/health';
export const CURATION_SETTINGS_PATH = '/dashboard/settings/customization/curation/settings';
export const CURATION_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/knowledge-curation/';

/** Actions that move data and therefore need the merge capability, mirroring the backend can_apply rule. */
export const CURATION_MERGE_ACTIONS = ['merge', 'unmerge'];

export const parseJsonObject = (value: string | null | undefined): Record<string, unknown> | null => {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
};

/**
 * useApiMutation hands GraphQL payload errors to onCompleted, not to onError: they are notified here and the caller
 * must stop before its success flow when this returns true.
 */
export const notifyPayloadErrors = (errors: PayloadError[] | null | undefined): boolean => {
  if (!errors || errors.length === 0) return false;
  MESSAGING$.notifyError(errors.map((error) => error.message).join('\n'));
  return true;
};

/** Tone of a design-system progress bar: success when conclusive, error when weak, neutral in between. */
export const confidenceTone = (confidence: number): 'success' | 'default' | 'error' => {
  if (confidence >= 0.85) return 'success';
  if (confidence >= 0.6) return 'default';
  return 'error';
};

/** Tone of a 0-100 score bar, with the thresholds of the score colors. */
export const scoreTone = (score: number): 'success' | 'default' | 'error' => {
  if (score >= 80) return 'success';
  if (score >= 60) return 'default';
  return 'error';
};

export const formatPercent = (value: number | null | undefined, digits = 0) => {
  if (value === null || value === undefined || Number.isNaN(value)) return '-';
  return `${(value * 100).toFixed(digits)}%`;
};

/**
 * Translated labels and colors of the curation vocabulary. Every label is a literal t_i18n call so the
 * translation checker sees it.
 */
const useCurationLabels = () => {
  const { t_i18n, fd, fldt } = useFormatter();
  const theme = useTheme<Theme>();

  const kindLabels: Record<string, string> = {
    merge: t_i18n('Duplicate'),
    alias: t_i18n('Alias'),
    split: t_i18n('Split'),
    contradiction: t_i18n('Contradiction'),
    stale: t_i18n('Stale knowledge'),
    relationship_conflict: t_i18n('Relationship conflict'),
    type_mismatch: t_i18n('Type mismatch'),
    field_precedence: t_i18n('Field precedence'),
  };
  const statusLabels: Record<string, string> = {
    open: t_i18n('Open'),
    accepted: t_i18n('Accepted'),
    rejected: t_i18n('Rejected'),
    auto_applied: t_i18n('Auto-applied'),
    reverted: t_i18n('Reverted'),
  };
  const actionLabels: Record<string, string> = {
    merge: t_i18n('Merge the entities'),
    add_aliases: t_i18n('Add the names as aliases'),
    unmerge: t_i18n('Unmerge'),
    fix_dates: t_i18n('Fix the dates'),
    resolve_attribution: t_i18n('Resolve the attribution'),
    unrevoke_indicator: t_i18n('Restore the indicator'),
    revoke: t_i18n('Revoke'),
    preserve_procedure: t_i18n('Preserve the procedure'),
    set_field: t_i18n('Restore the authoritative value'),
    acknowledge: t_i18n('Acknowledge'),
  };
  const detectorLabels: Record<string, string> = {
    normalization: t_i18n('Name normalization'),
    similarity: t_i18n('Name and description similarity'),
    behavior: t_i18n('Behavior anchoring'),
    contradiction: t_i18n('Contradictions'),
    staleness: t_i18n('Staleness'),
    relationship_conflict: t_i18n('Relationship conflicts'),
    combined: t_i18n('Combined evidence'),
    field_authority: t_i18n('Field authority'),
  };
  const evidenceLabels: Record<string, string> = {
    canonical_collision: t_i18n('Same canonical name'),
    shared_alias: t_i18n('Shared alias'),
    taxonomy: t_i18n('Public name catalogue'),
    trigram: t_i18n('Name similarity'),
    description_similarity: t_i18n('Description similarity'),
    graph_similarity: t_i18n('Graph similarity'),
    attack_overlap: t_i18n('ATT&CK techniques overlap'),
    shared_tools: t_i18n('Shared tools and malware'),
    shared_infrastructure: t_i18n('Shared infrastructure'),
    victimology: t_i18n('Victimology'),
    co_attribution: t_i18n('Co-attribution'),
    source_agreement: t_i18n('Source agreement'),
    date_inversion: t_i18n('Date inversion'),
    attribution_conflict: t_i18n('Attribution conflict'),
    revoked_indicator: t_i18n('Revoked indicator'),
    staleness: t_i18n('No recent activity'),
    decayed_indicator: t_i18n('Decayed indicator'),
    procedure_conflict: t_i18n('Procedure conflict'),
    type_collision: t_i18n('Type collision'),
    merged_entity: t_i18n('Merged entity'),
    field_conflict: t_i18n('Field conflict'),
  };
  const mergeStatusLabels: Record<string, string> = {
    active: t_i18n('Applied'),
    reverted: t_i18n('Undone'),
    partially_reverted: t_i18n('Partially undone'),
    irreversible: t_i18n('Not reversible'),
  };
  const decisionLabels: Record<string, string> = {
    alias: t_i18n('Alias'),
    merge: t_i18n('Merge'),
    distinct: t_i18n('Distinct'),
    skip: t_i18n('Skip'),
  };
  const sourceClassLabels: Record<string, string> = {
    any: t_i18n('Any source'),
    connector: t_i18n('Connectors only'),
    manual: t_i18n('Manual edits only'),
  };
  const conflictModeLabels: Record<string, string> = {
    procedures_array: t_i18n('Keep one relationship with all procedures'),
    note: t_i18n('Keep the procedure in a note'),
    detect_only: t_i18n('Detect only'),
  };
  const healthComponentLabels: Record<string, string> = {
    duplicates: t_i18n('Duplicates'),
    duplicate_rate: t_i18n('Duplicate rate'),
    contradictions: t_i18n('Contradictions'),
    staleness: t_i18n('Staleness'),
    stale_share: t_i18n('Stale share'),
    alias_coverage: t_i18n('Alias coverage'),
    source_conflicts: t_i18n('Source conflicts'),
    source_conflict_rate: t_i18n('Source conflict rate'),
  };
  const exclusionLabels: Record<string, string> = {
    not_open: t_i18n('Already decided'),
    kind_not_covered: t_i18n('Proposal kind not covered by the policy'),
    entity_type_not_covered: t_i18n('Entity type not covered by the policy'),
    below_threshold: t_i18n('Confidence below the threshold'),
    source_class_mismatch: t_i18n('Source class does not match'),
    cross_markings: t_i18n('Subjects with different markings'),
    cross_organizations: t_i18n('Subjects shared with different organizations'),
    open_contradiction: t_i18n('Open contradiction on a subject'),
    adjudication_missing: t_i18n('No adjudication yet'),
    adjudication_disagrees: t_i18n('The adjudication disagrees'),
    manual_choice_required: t_i18n('Needs a human choice'),
    subject_missing: t_i18n('A subject no longer exists'),
  };
  const weekDayLabels: Record<number, string> = {
    0: t_i18n('Sunday'),
    1: t_i18n('Monday'),
    2: t_i18n('Tuesday'),
    3: t_i18n('Wednesday'),
    4: t_i18n('Thursday'),
    5: t_i18n('Friday'),
    6: t_i18n('Saturday'),
  };

  const neutral = theme.palette.text?.secondary ?? '';
  const success = theme.palette.success.main ?? neutral;
  const warning = theme.palette.warn.main ?? neutral;
  const danger = theme.palette.error.main ?? neutral;

  const statusColor = (status: string): string => {
    switch (status) {
      case 'open': return warning;
      case 'accepted':
      case 'auto_applied':
      case 'active': return success;
      case 'rejected':
      case 'irreversible': return danger;
      default: return neutral;
    }
  };
  const confidenceColor = (confidence: number): string => {
    if (confidence >= 0.85) return success;
    if (confidence >= 0.6) return warning;
    return danger;
  };
  const healthColor = (score: number): string => {
    if (score >= 80) return success;
    if (score >= 60) return warning;
    return danger;
  };
  /** A score change reads from its direction, never from the score it reached. */
  const trendColor = (trend: number): string => (trend >= 0 ? success : danger);

  const label = (labels: Record<string, string>, key: string | null | undefined) => (key ? labels[key] ?? key : '-');

  const dateFieldLabels: Record<string, string> = {
    first_seen: t_i18n('First seen'),
    last_seen: t_i18n('Last seen'),
    valid_from: t_i18n('Valid from'),
    valid_until: t_i18n('Valid until'),
  };

  /**
   * The explanation of an evidence item in the user's language, built from the parameters its detector recorded. An item
   * whose details lack one of them (recorded by an earlier version) keeps the explanation stored with it.
   */
  const explanation = (item: { evidence_type: string; score: number; description: string }, details: Record<string, unknown> | null): string => {
    const text = (key: string) => (typeof details?.[key] === 'string' ? details[key] as string : null);
    const count = (key: string) => (typeof details?.[key] === 'number' ? details[key] as number : null);
    const list = (key: string) => (Array.isArray(details?.[key]) ? details[key] as unknown[] : null);
    const percent = (value: number | null) => (value === null ? null : Math.round(value * 100));
    const quoted = (names: unknown[]) => names.filter((name): name is string => typeof name === 'string').map((name) => `"${name}"`).join(', ');
    // Earlier versions kept the first 50 shared identifiers only, without their count.
    const sharedIds = list('shared_ids');
    const sharedCount = count('shared_count') ?? (sharedIds && sharedIds.length < 50 ? sharedIds.length : null);
    const left = text('left_name');
    const right = text('right_name');
    const canonical = text('canonical');
    const cluster = text('cluster');
    const mitre = text('source') === 'mitre';
    const overlap = percent(item.score);
    switch (item.evidence_type) {
      case 'canonical_collision':
      case 'shared_alias':
      case 'type_collision': {
        if (!left || !right) break;
        if (cluster) {
          return mitre
            ? t_i18n('"{left}" and "{right}" are listed as names of the same object by MITRE ATT&CK ({cluster})', { values: { left, right, cluster } })
            : t_i18n('"{left}" and "{right}" are listed as names of the same object by the MISP galaxy ({cluster})', { values: { left, right, cluster } });
        }
        if (!canonical) break;
        const leftType = text('left_type');
        const rightType = text('right_type');
        if (item.evidence_type === 'type_collision' && leftType && rightType) {
          return t_i18n('"{left}" ({leftType}) and "{right}" ({rightType}) normalize to the same name "{canonical}" but have different types', {
            values: { left, right, canonical, leftType: t_i18n(`entity_${leftType}`), rightType: t_i18n(`entity_${rightType}`) },
          });
        }
        return details?.stripped === true
          ? t_i18n('"{left}" and "{right}" are the same name once vendor suffixes and qualifiers are removed ("{canonical}")', { values: { left, right, canonical } })
          : t_i18n('"{left}" and "{right}" normalize to the same name "{canonical}" (case, punctuation, separators, digits used as letters)', { values: { left, right, canonical } });
      }
      case 'taxonomy': {
        if (!cluster) break;
        if (left && right) {
          return mitre
            ? t_i18n('"{left}" and "{right}" are listed as names of the same object by MITRE ATT&CK ({cluster})', { values: { left, right, cluster } })
            : t_i18n('"{left}" and "{right}" are listed as names of the same object by the MISP galaxy ({cluster})', { values: { left, right, cluster } });
        }
        const aliases = list('aliases');
        const name = text('entity_name');
        if (!aliases || !name) break;
        return mitre
          ? t_i18n('MITRE ATT&CK ({cluster}) lists {count} name(s) of "{name}" that the entity does not carry yet', { values: { cluster, count: aliases.length, name } })
          : t_i18n('The MISP galaxy ({cluster}) lists {count} name(s) of "{name}" that the entity does not carry yet', { values: { cluster, count: aliases.length, name } });
      }
      case 'trigram': {
        const similarity = percent(count('similarity'));
        if (!left || !right || similarity === null) break;
        return t_i18n('"{left}" and "{right}" are {similarity}% similar (trigram similarity)', { values: { left, right, similarity } });
      }
      case 'description_similarity': {
        const similarity = percent(count('similarity'));
        const terms = list('shared_terms');
        if (similarity === null || !terms) break;
        return t_i18n('The descriptions are {similarity}% similar (shared terms: {terms})', { values: { similarity, terms: terms.join(', ') } });
      }
      case 'attack_overlap': {
        const leftCount = count('left_count');
        const rightCount = count('right_count');
        if (sharedCount === null || leftCount === null || rightCount === null || overlap === null) break;
        return t_i18n('{shared} ATT&CK techniques in common ({overlap}% overlap of {left} and {right})', { values: { shared: sharedCount, overlap, left: leftCount, right: rightCount } });
      }
      case 'shared_tools':
        if (sharedCount === null || overlap === null) break;
        return t_i18n('{count} tools or malware in common ({overlap}% overlap)', { values: { count: sharedCount, overlap } });
      case 'shared_infrastructure':
        if (sharedCount === null || overlap === null) break;
        return t_i18n('{count} infrastructure elements in common ({overlap}% overlap)', { values: { count: sharedCount, overlap } });
      case 'victimology':
        if (sharedCount === null || overlap === null) break;
        return t_i18n('{count} targeted sectors, locations or organizations in common ({overlap}% overlap)', { values: { count: sharedCount, overlap } });
      case 'co_attribution':
        if (sharedCount === null) break;
        return t_i18n('{count} campaign(s) or incident(s) attributed to both', { values: { count: sharedCount } });
      case 'graph_similarity':
        if (overlap === null) break;
        return t_i18n('Structural similarity of {similarity}% in the knowledge graph analytics', { values: { similarity: overlap } });
      case 'source_agreement':
        if (list('shared_sources')) return t_i18n('The same source maintains both entities separately, which suggests they are distinct');
        if (list('left_sources')) return t_i18n('The entities come from different sources, a typical pattern of vendor naming');
        break;
      case 'date_inversion': {
        const startField = text('start_field');
        const stopField = text('stop_field');
        const start = text('start');
        const stop = text('stop');
        if (!startField || !stopField || !start || !stop) break;
        return t_i18n('{startField} ({start}) is after {stopField} ({stop})', {
          values: { startField: dateFieldLabels[startField] ?? startField, start: fldt(start), stopField: dateFieldLabels[stopField] ?? stopField, stop: fldt(stop) },
        });
      }
      case 'attribution_conflict': {
        const attributed = text('attributed_name');
        const actors = list('actor_names')?.filter((name): name is string => typeof name === 'string');
        if (!attributed || !actors || actors.length === 0) break;
        const joined = actors.map((actor) => `"${actor}"`).reduce((previous, next) => t_i18n('{previous} and to {next}', { values: { previous, next } }));
        return t_i18n('"{attributed}" is attributed to {attributions}: these actors were decided to be distinct and no source attributes it to both', {
          values: { attributed, attributions: joined },
        });
      }
      case 'revoked_indicator': {
        const name = text('indicator_name');
        const observables = list('observables');
        if (!name || !observables) break;
        return t_i18n('Indicator "{name}" is revoked while {count} observable(s) it is based on are still active', { values: { name, count: observables.length } });
      }
      case 'merged_entity': {
        const name = text('entity_name');
        const sources = list('source_names');
        if (!name || !sources) break;
        return t_i18n('"{name}" results from a merge with {sources} and is now involved in a contradiction', { values: { name, sources: quoted(sources) } });
      }
      case 'staleness': {
        const lastActivity = text('last_activity');
        const months = count('months');
        if (!lastActivity || months === null) break;
        return t_i18n('No update and no new relationship since {date} (more than {months} months)', { values: { date: fd(lastActivity), months } });
      }
      case 'decayed_indicator': {
        const score = count('score');
        const revokeScore = count('revoke_score');
        if (score === null || revokeScore === null) break;
        return t_i18n('The decayed score ({score}) is at or below the revoke score ({revokeScore}) but the indicator is still active', { values: { score, revokeScore } });
      }
      case 'procedure_conflict': {
        const from = text('from_name');
        const to = text('to_name');
        if (!from || !to) break;
        return t_i18n('The procedure of "{from} uses {to}" was replaced by a different procedure from another source', { values: { from, to } });
      }
      case 'field_conflict': {
        const field = text('field');
        if (!field) break;
        return t_i18n('"{field}" was overwritten by a less authoritative source according to the field authority rules', { values: { field } });
      }
      default:
        break;
    }
    return item.description;
  };

  return {
    kind: (key?: string | null) => label(kindLabels, key),
    status: (key?: string | null) => label(statusLabels, key),
    action: (key?: string | null) => label(actionLabels, key),
    detector: (key?: string | null) => label(detectorLabels, key),
    /** What found a proposal: alias proposals come from the public name catalogues, not from a name comparison. */
    foundBy: (kind?: string | null, detector?: string | null) => (kind === 'alias'
      ? t_i18n('Public name catalogues (MITRE ATT&CK, MISP galaxy)')
      : label(detectorLabels, detector)),
    evidence: (key?: string | null) => label(evidenceLabels, key),
    explanation,
    /** A merge whose retention window is over reads "Expired"; other irreversible merges read "Not reversible". */
    mergeStatus: (key?: string | null, reversibleUntil?: string | null) => {
      if (key === 'irreversible' && reversibleUntil && new Date(reversibleUntil).getTime() <= Date.now()) return t_i18n('Expired');
      return label(mergeStatusLabels, key);
    },
    /** Why a merge cannot be undone, as one sentence, from the reason code the platform recorded. */
    irreversibility: (reason: string, reversibleUntil?: string | null) => {
      switch (reason) {
        case 'too_many_removed_relationships':
          return t_i18n('This merge cannot be undone: it removed more duplicated relationships than a merge record can keep.');
        case 'too_many_moved_relationships':
          return t_i18n('This merge cannot be undone: it moved more relationships than a merge record can keep.');
        case 'merge_interrupted':
          return t_i18n('This merge cannot be undone: it was interrupted before all the entities were merged.');
        case 'merged_entity_deleted':
          return t_i18n('This merge can no longer be undone: the merged entity was deleted before the merge record was completed.');
        case 'retention_over':
          return t_i18n('This merge can no longer be undone: its retention window ended on {date}.', { values: { date: fldt(reversibleUntil) } });
        default:
          return t_i18n('This merge can no longer be undone: {reason}', { values: { reason } });
      }
    },
    decision: (key?: string | null) => label(decisionLabels, key),
    sourceClass: (key?: string | null) => label(sourceClassLabels, key),
    conflictMode: (key?: string | null) => label(conflictModeLabels, key),
    healthComponent: (key?: string | null) => label(healthComponentLabels, key),
    exclusion: (key?: string | null) => label(exclusionLabels, key),
    impact: (key: string) => {
      const [kind, types] = key.split(':');
      const typeLabels = (types ?? '').split('+').filter(Boolean).map((type) => t_i18n(`entity_${type}`));
      return `${label(kindLabels, kind)}${typeLabels.length > 0 ? ` - ${typeLabels.join(', ')}` : ''}`;
    },
    weekDay: (day: number) => weekDayLabels[day] ?? String(day),
    statusColor,
    confidenceColor,
    healthColor,
    trendColor,
  };
};

export default useCurationLabels;
