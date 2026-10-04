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
  const { t_i18n } = useFormatter();
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
    taxonomy: t_i18n('Vendor taxonomy'),
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

  return {
    kind: (key?: string | null) => label(kindLabels, key),
    status: (key?: string | null) => label(statusLabels, key),
    action: (key?: string | null) => label(actionLabels, key),
    detector: (key?: string | null) => label(detectorLabels, key),
    evidence: (key?: string | null) => label(evidenceLabels, key),
    /** A merge whose retention window is over reads "Expired"; other irreversible merges read "Not reversible". */
    mergeStatus: (key?: string | null, reversibleUntil?: string | null) => {
      if (key === 'irreversible' && reversibleUntil && new Date(reversibleUntil).getTime() <= Date.now()) return t_i18n('Expired');
      return label(mergeStatusLabels, key);
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
