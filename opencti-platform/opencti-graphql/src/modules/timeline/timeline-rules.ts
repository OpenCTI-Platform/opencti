import { FROM_START, UNTIL_END } from '../../utils/format';
import type { TimelineKindValue, TimelineLaneValue, TimelinePrecisionValue, TimelineSourceState } from './timeline-types';

// region derivation input
// The loader (timeline-loader.ts) reads the database and normalizes everything a rule needs
// into this structure. Rules are pure functions of it, which keeps them deterministic and testable.

export interface TimelineElementData {
  id: string;
  standard_id: string;
  entity_type: string;
  name: string;
  markings: string[];
  labels?: string[];
  created?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  creator_ids?: string[];
  created_by_id?: string | null;
  confidence?: number | null;
  description?: string | null;
  // temporal attributes
  first_seen?: string | null;
  last_seen?: string | null;
  start_time?: string | null;
  stop_time?: string | null;
  first_observed?: string | null;
  last_observed?: string | null;
  number_observed?: number | null;
  attribute_count?: number | null;
  valid_from?: string | null;
  valid_until?: string | null;
  published?: string | null;
  due_date?: string | null;
  workflow_id?: string | null;
  kill_chain_phase_ids?: string[];
  // relationships
  relationship_type?: string;
  from_id?: string;
  to_id?: string;
  from_type?: string;
  to_type?: string;
  from_name?: string;
  to_name?: string;
  // external references
  source_name?: string;
  external_id?: string;
  url?: string;
  // free soft-check payload (attributes of types owned by other modules)
  extra?: Record<string, unknown>;
}

export interface TimelineHistoryChange {
  field: string; // `<entity type>--<attribute>`
  added: Array<{ raw: string; name?: string }>;
  removed: Array<{ raw: string; name?: string }>;
}

export interface TimelineHistoryEntry {
  id: string;
  timestamp: string;
  event_scope: string; // create | update | delete | merge
  entity_id: string;
  entity_type: string;
  entity_name: string;
  message: string;
  user_id?: string | null;
  markings: string[];
  changes: TimelineHistoryChange[];
}

export interface TimelineFileData {
  id: string;
  name: string;
  version: string;
  mime_type?: string;
  markings: string[];
}

export interface TimelineKillChainPhaseData {
  id: string;
  phase_name: string;
  kill_chain_name: string;
  order: number;
}

export interface TimelineStatusData {
  id: string;
  name: string;
  order: number;
  type: string;
  is_final: boolean;
}

export interface TimelineContainerData extends TimelineElementData {
  is_case: boolean;
  files: TimelineFileData[];
}

export interface TimelineSoftSources {
  coverageResults: TimelineElementData[];
  coverageRelationships: TimelineElementData[];
  huntRuns: TimelineElementData[];
  deployments: TimelineElementData[];
  investigationRuns: TimelineElementData[];
}

export interface TimelineDerivationInput {
  container: TimelineContainerData;
  // entities in the scope of the timeline (contained objects of a case, related entities of an incident)
  entities: TimelineElementData[];
  // stix core relationships and sightings in scope
  relationships: TimelineElementData[];
  tasks: TimelineElementData[];
  notes: TimelineElementData[];
  opinions: TimelineElementData[];
  reports: TimelineElementData[];
  externalReferences: TimelineElementData[];
  history: TimelineHistoryEntry[];
  taskHistory: TimelineHistoryEntry[];
  killChainPhases: Map<string, TimelineKillChainPhaseData>;
  statuses: Map<string, TimelineStatusData>;
  soft: TimelineSoftSources;
  securityPlatformType: string;
}
// endregion

// region derivation output
export interface DerivedTimelineEvent {
  rule_id: string;
  kind: TimelineKindValue;
  lane: TimelineLaneValue;
  // id of the history entry or sub-item when an element produces several events of the same kind
  discriminator?: string;
  element_id: string | null;
  element_type: string | null;
  // Other elements whose data the event carries (the relationships dating a technique, the run behind a hunt or a
  // finding): each is read like the element, so a reader who cannot access one of them never sees the event
  source_ids?: string[];
  event_time: string;
  event_end_time?: string | null;
  time_precision: TimelinePrecisionValue;
  name: string;
  description?: string | null;
  markings: string[];
  confidence?: number | null;
  ordering_hint?: number | null;
  created_by_id?: string | null;
  creator_ids?: string[];
  source_state?: TimelineSourceState | null;
}

export interface TimelineRule {
  id: string;
  label: string;
  kinds: TimelineKindValue[];
  // Soft-check rules consume types owned by other modules and only activate when those types are registered
  isAvailable?: () => boolean;
  derive: (input: TimelineDerivationInput) => DerivedTimelineEvent[];
}
// endregion

// region helpers
const RULE_TECHNIQUE = 'technique-kill-chain';
export const RULE_TASK_CONTAINMENT = 'task-containment';
export const RULE_WORKFLOW_CLOSURE = 'workflow-closure';

export const CONTAINMENT_LABEL = 'containment';
const UNKNOWN_PHASE_ORDER = 9999;

/** Parse a date, returning null for empty values and for the open-interval sentinels used by the platform. */
export const toTimelineTime = (value: string | Date | null | undefined): number | null => {
  if (value === null || value === undefined || value === '') return null;
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return null;
  if (time <= FROM_START || time >= UNTIL_END) return null;
  return time;
};

const iso = (time: number): string => new Date(time).toISOString();

const uniq = (values: string[]): string[] => Array.from(new Set(values.filter((v) => !!v)));

const mergeMarkings = (...markings: Array<string[] | undefined>): string[] => uniq(markings.flatMap((m) => m ?? []));

const windowOf = (start: string | null | undefined, end: string | null | undefined) => {
  const startTime = toTimelineTime(start);
  const endTime = toTimelineTime(end);
  if (startTime === null && endTime === null) return null;
  const from = startTime ?? endTime as number;
  const to = endTime !== null && endTime > from ? endTime : null;
  return { from, to };
};

const formatCount = (count: number | null | undefined, singular: string, plural: string) => {
  if (count === null || count === undefined) return undefined;
  return `${count} ${count === 1 ? singular : plural}`;
};

const changeField = (change: TimelineHistoryChange) => change.field.split('--')[1] ?? change.field;
// endregion

// region adversary rules
const ENTITY_SEEN_KINDS: Record<string, TimelineKindValue> = {
  Infrastructure: 'infrastructure_seen',
  Malware: 'malware_seen',
  Tool: 'malware_seen',
  'Intrusion-Set': 'threat_seen',
  Campaign: 'threat_seen',
  'Threat-Actor-Group': 'threat_seen',
  'Threat-Actor-Individual': 'threat_seen',
  Incident: 'incident_seen',
};

const entitySeenRule: TimelineRule = {
  id: 'entity-first-last-seen',
  label: 'First and last seen of incidents, infrastructures, malware and threats',
  kinds: ['infrastructure_seen', 'malware_seen', 'threat_seen', 'incident_seen'],
  derive: (input) => {
    const candidates = [...input.entities];
    // An incident timeline starts with the incident itself
    if (!input.container.is_case) candidates.push(input.container);
    return candidates.flatMap((element) => {
      const kind = ENTITY_SEEN_KINDS[element.entity_type];
      if (!kind) return [];
      const window = windowOf(element.first_seen, element.last_seen);
      if (!window) return [];
      return [{
        rule_id: 'entity-first-last-seen',
        kind,
        lane: 'adversary',
        element_id: element.id,
        element_type: element.entity_type,
        event_time: iso(window.from),
        event_end_time: window.to !== null ? iso(window.to) : null,
        time_precision: 'exact',
        name: `${element.entity_type} ${element.name} active`,
        description: element.description,
        markings: mergeMarkings(element.markings),
        confidence: element.confidence,
      } satisfies DerivedTimelineEvent];
    });
  },
};

const observedDataRule: TimelineRule = {
  id: 'observed-data-window',
  label: 'Observation windows of observed data',
  kinds: ['observed_window'],
  derive: (input) => input.entities
    .filter((element) => element.entity_type === 'Observed-Data')
    .flatMap((element) => {
      const window = windowOf(element.first_observed, element.last_observed);
      if (!window) return [];
      return [{
        rule_id: 'observed-data-window',
        kind: 'observed_window',
        lane: 'adversary',
        element_id: element.id,
        element_type: element.entity_type,
        event_time: iso(window.from),
        event_end_time: window.to !== null ? iso(window.to) : null,
        time_precision: 'exact',
        name: `Observed data ${element.name}`,
        description: formatCount(element.number_observed, 'observation', 'observations'),
        markings: mergeMarkings(element.markings),
        confidence: element.confidence,
      } satisfies DerivedTimelineEvent];
    }),
};

const sightingRule: TimelineRule = {
  id: 'sighting-window',
  label: 'Sightings, platform sightings land in the detection lane',
  kinds: ['sighting'],
  derive: (input) => input.relationships
    .filter((element) => element.entity_type === 'stix-sighting-relationship')
    .flatMap((element) => {
      const window = windowOf(element.first_seen, element.last_seen) ?? windowOf(element.created, null);
      if (!window) return [];
      const isPlatformSighting = element.to_type === input.securityPlatformType;
      return [{
        rule_id: 'sighting-window',
        kind: 'sighting',
        lane: isPlatformSighting ? 'detection' : 'adversary',
        element_id: element.id,
        element_type: element.entity_type,
        event_time: iso(window.from),
        event_end_time: window.to !== null ? iso(window.to) : null,
        time_precision: toTimelineTime(element.first_seen) !== null ? 'exact' : 'approximate',
        name: `${element.from_name ?? 'Unknown'} sighted in ${element.to_name ?? 'Unknown'}`,
        description: formatCount(element.attribute_count, 'sighting', 'sightings'),
        markings: mergeMarkings(element.markings),
        confidence: element.confidence,
      } satisfies DerivedTimelineEvent];
    }),
};

/** Compute the adversary activity window from every element carrying an exact adversary time. */
export const computeAdversaryWindow = (input: TimelineDerivationInput): { from: number; to: number } | null => {
  const times: number[] = [];
  const push = (start: string | null | undefined, end: string | null | undefined) => {
    const window = windowOf(start, end);
    if (window) {
      times.push(window.from);
      if (window.to !== null) times.push(window.to);
    }
  };
  const seenSources = input.container.is_case ? input.entities : [...input.entities, input.container];
  seenSources.filter((e) => ENTITY_SEEN_KINDS[e.entity_type]).forEach((e) => push(e.first_seen, e.last_seen));
  input.entities.filter((e) => e.entity_type === 'Observed-Data').forEach((e) => push(e.first_observed, e.last_observed));
  input.relationships.forEach((r) => {
    if (r.entity_type === 'stix-sighting-relationship') {
      if (r.to_type !== input.securityPlatformType) push(r.first_seen, r.last_seen);
    } else {
      push(r.start_time, r.stop_time);
    }
  });
  if (times.length === 0) return null;
  return { from: Math.min(...times), to: Math.max(...times) };
};

const techniquePhaseOrder = (input: TimelineDerivationInput, technique: TimelineElementData): number => {
  const orders = (technique.kill_chain_phase_ids ?? [])
    .map((id) => input.killChainPhases.get(id)?.order)
    .filter((order): order is number => order !== undefined && order !== null);
  return orders.length > 0 ? Math.min(...orders) : UNKNOWN_PHASE_ORDER;
};

const techniquePhaseNames = (input: TimelineDerivationInput, technique: TimelineElementData): string[] => {
  return (technique.kill_chain_phase_ids ?? [])
    .map((id) => input.killChainPhases.get(id)?.phase_name)
    .filter((name): name is string => !!name);
};

const techniqueRule: TimelineRule = {
  id: RULE_TECHNIQUE,
  label: 'Techniques in kill chain order, with exact windows from uses and targets relationships',
  kinds: ['technique_used'],
  derive: (input) => {
    const techniques = input.entities.filter((e) => e.entity_type === 'Attack-Pattern');
    if (techniques.length === 0) return [];
    const timedRelationships = input.relationships.filter((r) => (r.relationship_type === 'uses' || r.relationship_type === 'targets')
      && toTimelineTime(r.start_time) !== null);
    const events: DerivedTimelineEvent[] = [];
    const untimed: TimelineElementData[] = [];
    techniques.forEach((technique) => {
      const related = timedRelationships.filter((r) => r.to_id === technique.id || r.from_id === technique.id);
      const phases = techniquePhaseNames(input, technique);
      if (related.length > 0) {
        const starts = related.map((r) => toTimelineTime(r.start_time) as number);
        const stops = related.map((r) => toTimelineTime(r.stop_time));
        const from = Math.min(...starts);
        // One relationship without an end keeps the technique open-ended: the window never ends before one of them starts
        const to = stops.every((t): t is number => t !== null) ? Math.max(...stops) : null;
        events.push({
          rule_id: RULE_TECHNIQUE,
          kind: 'technique_used',
          lane: 'adversary',
          element_id: technique.id,
          element_type: technique.entity_type,
          source_ids: related.map((r) => r.id),
          event_time: iso(from),
          event_end_time: to !== null && to > from ? iso(to) : null,
          time_precision: 'exact',
          name: `Technique ${technique.name}`,
          description: phases.length > 0 ? `Kill chain phases: ${phases.join(', ')}` : technique.description,
          markings: mergeMarkings(technique.markings, ...related.map((r) => r.markings)),
          confidence: technique.confidence,
          ordering_hint: techniquePhaseOrder(input, technique),
        });
      } else {
        untimed.push(technique);
      }
    });
    if (untimed.length > 0) {
      // Techniques without explicit times are spread over the adversary window in kill chain order
      const window = computeAdversaryWindow(input)
        ?? { from: toTimelineTime(input.container.first_seen) ?? toTimelineTime(input.container.created) ?? toTimelineTime(input.container.created_at) ?? 0, to: 0 };
      const span = window.to > window.from ? window.to - window.from : 0;
      const sorted = [...untimed].sort((a, b) => {
        const orderDiff = techniquePhaseOrder(input, a) - techniquePhaseOrder(input, b);
        return orderDiff !== 0 ? orderDiff : a.name.localeCompare(b.name);
      });
      sorted.forEach((technique, index) => {
        const phases = techniquePhaseNames(input, technique);
        const time = span > 0 ? window.from + Math.round(((index + 1) / (sorted.length + 1)) * span) : window.from;
        if (time <= 0) return;
        events.push({
          rule_id: RULE_TECHNIQUE,
          kind: 'technique_used',
          lane: 'adversary',
          element_id: technique.id,
          element_type: technique.entity_type,
          event_time: iso(time),
          event_end_time: null,
          time_precision: 'approximate',
          name: `Technique ${technique.name}`,
          description: phases.length > 0 ? `Kill chain phases: ${phases.join(', ')} (placed by kill chain order)` : 'Placed by kill chain order',
          markings: mergeMarkings(technique.markings),
          confidence: technique.confidence,
          ordering_hint: index,
        });
      });
    }
    return events;
  },
};
// endregion

// region evidence rules
const indicatorRule: TimelineRule = {
  id: 'indicator-validity',
  label: 'Indicator validity windows',
  kinds: ['indicator_valid'],
  derive: (input) => input.entities
    .filter((e) => e.entity_type === 'Indicator')
    .flatMap((indicator) => {
      const window = windowOf(indicator.valid_from, indicator.valid_until);
      if (!window) return [];
      return [{
        rule_id: 'indicator-validity',
        kind: 'indicator_valid',
        lane: 'evidence',
        element_id: indicator.id,
        element_type: indicator.entity_type,
        event_time: iso(window.from),
        event_end_time: window.to !== null ? iso(window.to) : null,
        time_precision: 'exact',
        name: `Indicator ${indicator.name} valid`,
        description: indicator.description,
        markings: mergeMarkings(indicator.markings),
        confidence: indicator.confidence,
      } satisfies DerivedTimelineEvent];
    }),
};

const reportRule: TimelineRule = {
  id: 'report-published',
  label: 'Publication of reports in scope',
  kinds: ['report_published'],
  derive: (input) => input.reports.flatMap((report) => {
    const time = toTimelineTime(report.published) ?? toTimelineTime(report.created);
    if (time === null) return [];
    return [{
      rule_id: 'report-published',
      kind: 'report_published',
      lane: 'evidence',
      element_id: report.id,
      element_type: report.entity_type,
      event_time: iso(time),
      time_precision: toTimelineTime(report.published) !== null ? 'exact' : 'approximate',
      name: `Report ${report.name} published`,
      description: report.description,
      markings: mergeMarkings(report.markings),
      confidence: report.confidence,
      created_by_id: report.created_by_id,
    } satisfies DerivedTimelineEvent];
  }),
};

const externalReferenceRule: TimelineRule = {
  id: 'external-reference-published',
  label: 'Publication of external references of the container',
  kinds: ['reference_published'],
  derive: (input) => input.externalReferences.flatMap((reference) => {
    const time = toTimelineTime(reference.created) ?? toTimelineTime(reference.created_at);
    if (time === null) return [];
    const name = reference.external_id ? `${reference.source_name} (${reference.external_id})` : reference.source_name ?? reference.name;
    return [{
      rule_id: 'external-reference-published',
      kind: 'reference_published',
      lane: 'evidence',
      element_id: reference.id,
      element_type: reference.entity_type,
      event_time: iso(time),
      time_precision: 'day',
      name: `Reference ${name}`,
      description: reference.url ?? reference.description,
      markings: [],
    } satisfies DerivedTimelineEvent];
  }),
};

const fileRule: TimelineRule = {
  id: 'file-uploaded',
  label: 'Files uploaded to the container',
  kinds: ['file_uploaded'],
  derive: (input) => input.container.files.flatMap((file) => {
    const time = toTimelineTime(file.version);
    if (time === null) return [];
    return [{
      rule_id: 'file-uploaded',
      kind: 'file_uploaded',
      lane: 'evidence',
      discriminator: file.id,
      element_id: input.container.id,
      element_type: input.container.entity_type,
      event_time: iso(time),
      time_precision: 'exact',
      name: `File ${file.name} uploaded`,
      description: file.mime_type,
      markings: mergeMarkings(file.markings),
    } satisfies DerivedTimelineEvent];
  }),
};
// endregion

// region response rules
const caseOpenedRule: TimelineRule = {
  id: 'case-opened',
  label: 'Opening of the case',
  kinds: ['case_opened'],
  derive: (input) => {
    if (!input.container.is_case) return [];
    const time = toTimelineTime(input.container.created) ?? toTimelineTime(input.container.created_at);
    if (time === null) return [];
    return [{
      rule_id: 'case-opened',
      kind: 'case_opened',
      lane: 'response',
      element_id: input.container.id,
      element_type: input.container.entity_type,
      event_time: iso(time),
      time_precision: 'exact',
      name: `Case ${input.container.name} opened`,
      markings: [],
      created_by_id: input.container.created_by_id,
      creator_ids: input.container.creator_ids,
    }];
  },
};

const isFinalStatus = (input: TimelineDerivationInput, statusId: string | null | undefined) => {
  return !!statusId && input.statuses.get(statusId)?.is_final === true;
};

/**
 * Find when a task was first completed, from its history: the completion stays a fact of the case when the task is
 * reopened later. A task in a final status without such a history entry falls back to its last update.
 */
const taskCompletionTime = (input: TimelineDerivationInput, task: TimelineElementData): { time: number; exact: boolean } | null => {
  const transitions = input.taskHistory
    .filter((entry) => entry.entity_id === task.id)
    .flatMap((entry) => entry.changes
      .filter((change) => changeField(change) === 'x_opencti_workflow_id' && change.added.some((a) => isFinalStatus(input, a.raw)))
      .map(() => toTimelineTime(entry.timestamp)))
    .filter((t): t is number => t !== null);
  if (transitions.length > 0) return { time: Math.min(...transitions), exact: true };
  if (!isFinalStatus(input, task.workflow_id)) return null;
  const fallback = toTimelineTime(task.updated_at);
  return fallback !== null ? { time: fallback, exact: false } : null;
};

const taskRule: TimelineRule = {
  id: 'task-lifecycle',
  label: 'Tasks created, due and completed (tasks labelled containment drive the containment anchor)',
  kinds: ['task_created', 'task_due', 'task_completed'],
  derive: (input) => input.tasks.flatMap((task) => {
    const events: DerivedTimelineEvent[] = [];
    const base = {
      lane: 'response' as const,
      element_id: task.id,
      element_type: task.entity_type,
      markings: mergeMarkings(task.markings),
      created_by_id: task.created_by_id,
      creator_ids: task.creator_ids,
    };
    const created = toTimelineTime(task.created) ?? toTimelineTime(task.created_at);
    if (created !== null) {
      events.push({ ...base, rule_id: 'task-lifecycle', kind: 'task_created', event_time: iso(created), time_precision: 'exact', name: `Task ${task.name} created`, description: task.description });
    }
    const due = toTimelineTime(task.due_date);
    if (due !== null) {
      events.push({ ...base, rule_id: 'task-lifecycle', kind: 'task_due', event_time: iso(due), time_precision: 'exact', name: `Task ${task.name} due` });
    }
    const completion = taskCompletionTime(input, task);
    if (completion) {
      const isContainment = (task.labels ?? []).some((label) => label.toLowerCase() === CONTAINMENT_LABEL);
      events.push({
        ...base,
        rule_id: isContainment ? RULE_TASK_CONTAINMENT : 'task-lifecycle',
        kind: 'task_completed',
        event_time: iso(completion.time),
        time_precision: completion.exact ? 'exact' : 'approximate',
        name: `Task ${task.name} completed`,
      });
    }
    return events;
  }),
};

const workflowRule: TimelineRule = {
  id: 'workflow-status',
  label: 'Workflow status transitions read from the history',
  kinds: ['status_changed'],
  derive: (input) => input.history.flatMap((entry) => {
    if (entry.entity_id !== input.container.id) return [];
    const time = toTimelineTime(entry.timestamp);
    if (time === null) return [];
    return entry.changes
      .filter((change) => changeField(change) === 'x_opencti_workflow_id' && change.added.length > 0)
      .map((change) => {
        const statusId = change.added[0].raw;
        const status = input.statuses.get(statusId);
        const statusName = status?.name ?? change.added[0].name ?? statusId;
        const previous = change.removed[0] ? (input.statuses.get(change.removed[0].raw)?.name ?? change.removed[0].name) : undefined;
        return {
          rule_id: status?.is_final ? RULE_WORKFLOW_CLOSURE : 'workflow-status',
          kind: 'status_changed' as const,
          lane: 'response' as const,
          discriminator: entry.id,
          element_id: input.container.id,
          element_type: input.container.entity_type,
          event_time: iso(time),
          time_precision: 'exact' as const,
          name: `Status changed to ${statusName}`,
          description: previous ? `From ${previous}` : undefined,
          markings: mergeMarkings(entry.markings),
          creator_ids: entry.user_id ? [entry.user_id] : [],
        };
      });
  }),
};

const assignmentRule: TimelineRule = {
  id: 'assignment',
  label: 'Assignees and participants added, read from the history',
  kinds: ['assigned'],
  derive: (input) => input.history.flatMap((entry) => {
    if (entry.entity_id !== input.container.id) return [];
    const time = toTimelineTime(entry.timestamp);
    if (time === null) return [];
    return entry.changes
      .filter((change) => ['objectAssignee', 'objectParticipant'].includes(changeField(change)) && change.added.length > 0)
      .map((change) => {
        const isParticipant = changeField(change) === 'objectParticipant';
        const names = change.added.map((a) => a.name ?? a.raw);
        return {
          rule_id: 'assignment',
          kind: 'assigned' as const,
          lane: 'response' as const,
          discriminator: `${entry.id}-${changeField(change)}`,
          element_id: input.container.id,
          element_type: input.container.entity_type,
          event_time: iso(time),
          time_precision: 'exact' as const,
          name: `${isParticipant ? 'Participant' : 'Assignee'} added: ${names.join(', ')}`,
          markings: mergeMarkings(entry.markings),
          creator_ids: entry.user_id ? [entry.user_id] : [],
          // The event names them: it is read like each of them, and carries their markings
          source_ids: change.added.map((a) => a.raw),
        };
      });
  }),
};

const containerContributionRule = (id: string, kind: 'note_added' | 'opinion_added', label: string, select: (input: TimelineDerivationInput) => TimelineElementData[]): TimelineRule => ({
  id,
  label,
  kinds: [kind],
  derive: (input) => select(input).flatMap((element) => {
    const time = toTimelineTime(element.created) ?? toTimelineTime(element.created_at);
    if (time === null) return [];
    return [{
      rule_id: id,
      kind,
      lane: 'response',
      element_id: element.id,
      element_type: element.entity_type,
      event_time: iso(time),
      time_precision: 'exact',
      name: kind === 'note_added' ? `Note ${element.name}` : `Opinion ${element.name}`,
      description: element.description,
      markings: mergeMarkings(element.markings),
      confidence: element.confidence,
      created_by_id: element.created_by_id,
      creator_ids: element.creator_ids,
    } satisfies DerivedTimelineEvent];
  }),
});

const noteRule = containerContributionRule('note-added', 'note_added', 'Notes written about the container', (input) => input.notes);
const opinionRule = containerContributionRule('opinion-added', 'opinion_added', 'Opinions given on the container', (input) => input.opinions);
// endregion

// region knowledge rules
// Up to this number of objects added at once, each object gets its own event (pointing to it, so that
// viewers only see the additions of the objects they can access). Above, a bulk addition (usually an
// import) is summarized in one event carrying a count only: names would leak past the access filter.
export const MAX_DETAILED_OBJECT_ADDITIONS = 10;

const objectAddedRule: TimelineRule = {
  id: 'object-added',
  label: 'Objects added to the case, read from the history',
  kinds: ['object_added'],
  derive: (input) => input.history.flatMap((entry): DerivedTimelineEvent[] => {
    if (entry.entity_id !== input.container.id) return [];
    const time = toTimelineTime(entry.timestamp);
    if (time === null) return [];
    const added = entry.changes
      .filter((change) => changeField(change) === 'objects')
      .flatMap((change) => change.added)
      .filter((a) => !!a.raw);
    if (added.length === 0) return [];
    const base = {
      rule_id: 'object-added',
      kind: 'object_added' as const,
      lane: 'knowledge' as const,
      event_time: iso(time),
      time_precision: 'exact' as const,
      markings: mergeMarkings(entry.markings),
      creator_ids: entry.user_id ? [entry.user_id] : [],
    };
    if (added.length > MAX_DETAILED_OBJECT_ADDITIONS) {
      return [{ ...base, discriminator: entry.id, element_id: null, element_type: null, name: `${added.length} objects added` }];
    }
    return added.map((object) => ({
      ...base,
      discriminator: `${entry.id}|${object.raw}`,
      element_id: object.raw,
      element_type: null,
      name: `${object.name ?? object.raw} added`,
    }));
  }),
};

const relationCreatedRule: TimelineRule = {
  id: 'relation-created',
  label: 'Relationships created in the scope of the timeline',
  kinds: ['relation_created'],
  derive: (input) => input.relationships
    .filter((r) => r.entity_type !== 'stix-sighting-relationship')
    .flatMap((relationship) => {
      const time = toTimelineTime(relationship.created_at) ?? toTimelineTime(relationship.created);
      if (time === null) return [];
      return [{
        rule_id: 'relation-created',
        kind: 'relation_created',
        lane: 'knowledge',
        element_id: relationship.id,
        element_type: relationship.entity_type,
        event_time: iso(time),
        time_precision: 'exact',
        name: `${relationship.from_name ?? 'Unknown'} ${relationship.relationship_type ?? 'related-to'} ${relationship.to_name ?? 'Unknown'}`,
        description: relationship.description,
        markings: mergeMarkings(relationship.markings),
        confidence: relationship.confidence,
        created_by_id: relationship.created_by_id,
        creator_ids: relationship.creator_ids,
      } satisfies DerivedTimelineEvent];
    }),
};

const mergeRule: TimelineRule = {
  id: 'merge',
  label: 'Merges of the container or of its objects, read from the history',
  kinds: ['merged'],
  derive: (input) => input.history
    .filter((entry) => entry.event_scope === 'merge')
    .flatMap((entry) => {
      const time = toTimelineTime(entry.timestamp);
      if (time === null) return [];
      return [{
        rule_id: 'merge',
        kind: 'merged',
        lane: 'knowledge',
        discriminator: entry.id,
        element_id: entry.entity_id,
        element_type: entry.entity_type,
        event_time: iso(time),
        time_precision: 'exact',
        name: `${entry.entity_name} merged`,
        description: entry.message,
        markings: mergeMarkings(entry.markings),
        creator_ids: entry.user_id ? [entry.user_id] : [],
      } satisfies DerivedTimelineEvent];
    }),
};
// endregion

// region detection and validation rules (soft checks)
const readExtra = (element: TimelineElementData, key: string): unknown => element.extra?.[key];
const readExtraString = (element: TimelineElementData, key: string): string | undefined => {
  const value = readExtra(element, key);
  if (value === null || value === undefined) return undefined;
  return String(value);
};

export const coverageResultRule: TimelineRule = {
  id: 'security-coverage-result',
  label: 'Security coverage results of the container (OpenAEV)',
  kinds: ['coverage_result'],
  derive: (input) => [
    ...input.soft.coverageResults.flatMap((result) => {
      const time = toTimelineTime(readExtraString(result, 'coverage_last_result')) ?? toTimelineTime(result.created_at);
      if (time === null) return [];
      const validTo = toTimelineTime(readExtraString(result, 'coverage_valid_to'));
      const scores = (readExtra(result, 'coverage_information') as Array<{ coverage_name: string; coverage_score: number }> | undefined) ?? [];
      return [{
        rule_id: 'security-coverage-result',
        kind: 'coverage_result' as const,
        lane: 'detection' as const,
        element_id: result.id,
        element_type: result.entity_type,
        event_time: iso(time),
        event_end_time: validTo !== null && validTo > time ? iso(validTo) : null,
        time_precision: 'exact' as const,
        name: `Coverage result ${result.name}`,
        description: scores.map((s) => `${s.coverage_name}: ${s.coverage_score}%`).join(', ') || undefined,
        markings: mergeMarkings(result.markings),
      }];
    }),
    ...input.soft.coverageRelationships.flatMap((relationship) => {
      const time = toTimelineTime(relationship.updated_at) ?? toTimelineTime(relationship.created_at);
      if (time === null) return [];
      const scores = (readExtra(relationship, 'coverage_information') as Array<{ coverage_name: string; coverage_score: number }> | undefined) ?? [];
      return [{
        rule_id: 'security-coverage-result',
        kind: 'coverage_result' as const,
        lane: 'detection' as const,
        element_id: relationship.id,
        element_type: relationship.entity_type,
        event_time: iso(time),
        time_precision: 'exact' as const,
        name: `Coverage of ${relationship.to_name ?? 'Unknown'}`,
        description: scores.map((s) => `${s.coverage_name}: ${s.coverage_score}%`).join(', ') || undefined,
        markings: mergeMarkings(relationship.markings),
      }];
    }),
  ],
};

export const huntRunRule: TimelineRule = {
  id: 'hunt-run',
  label: 'Hunt runs of the hunts in scope',
  kinds: ['hunt_run'],
  derive: (input) => {
    const huntNames = new Map(input.entities.filter((e) => e.entity_type === 'Hunt').map((e) => [e.id, e.name]));
    return input.soft.huntRuns.flatMap((run) => {
      const start = toTimelineTime(readExtraString(run, 'started_at')) ?? toTimelineTime(run.created_at);
      if (start === null) return [];
      const end = toTimelineTime(readExtraString(run, 'completed_at'));
      const status = readExtraString(run, 'hunt_run_status') ?? readExtraString(run, 'status');
      const hits = readExtra(run, 'hits_count') as number | undefined;
      const verdict = readExtraString(run, 'verdict');
      const huntId = readExtraString(run, 'hunt_id');
      const huntName = huntId ? huntNames.get(huntId) : undefined;
      return [{
        rule_id: 'hunt-run',
        kind: 'hunt_run' as const,
        lane: 'detection' as const,
        // A run points to its hunt when the hunt is in scope, to itself otherwise
        element_id: huntName ? huntId as string : run.id,
        element_type: huntName ? 'Hunt' : run.entity_type,
        source_ids: huntName ? [run.id] : [],
        discriminator: run.id,
        event_time: iso(start),
        event_end_time: end !== null && end > start ? iso(end) : null,
        time_precision: 'exact' as const,
        name: `Hunt run ${huntName ?? run.name}`,
        description: formatCount(hits, 'hit', 'hits'),
        markings: mergeMarkings(run.markings),
        source_state: { family: 'hunt_run', state: status ?? null, verdict: verdict ?? null },
      }];
    });
  },
};

export const deploymentRule: TimelineRule = {
  id: 'indicator-deployment',
  label: 'Deployments of the indicators in scope on security platforms',
  kinds: ['deployment'],
  derive: (input) => input.soft.deployments.flatMap((deployment) => {
    const start = toTimelineTime(readExtraString(deployment, 'deployed_at')) ?? toTimelineTime(deployment.created_at);
    if (start === null) return [];
    const end = toTimelineTime(readExtraString(deployment, 'removed_at'));
    const status = readExtraString(deployment, 'deployment_status');
    const validation = readExtraString(deployment, 'validation_status');
    const hits = readExtra(deployment, 'hit_count') as number | undefined;
    return [{
      rule_id: 'indicator-deployment',
      kind: 'deployment' as const,
      lane: 'detection' as const,
      element_id: deployment.id,
      element_type: deployment.entity_type,
      event_time: iso(start),
      event_end_time: end !== null && end > start ? iso(end) : null,
      time_precision: 'exact' as const,
      name: `${deployment.from_name ?? 'Indicator'} deployed on ${deployment.to_name ?? 'Unknown'}`,
      description: formatCount(hits, 'hit', 'hits'),
      markings: mergeMarkings(deployment.markings),
      source_state: { family: 'deployment', state: status ?? null, validation: validation ?? null },
    }];
  }),
};

// Steps of an investigation run: the engine shape (action, source_name, findings_count) and the
// former ledger shape (tool, description, duration_ms), read side by side while #18672 migrates.
interface InvestigationStepEntry {
  id?: string;
  position?: number;
  action?: string | null;
  source_name?: string | null;
  status?: string | null;
  findings_count?: number | null;
  started_at?: string | null;
  completed_at?: string | null;
  tool?: string | null;
  description?: string | null;
  duration_ms?: number | null;
}
interface InvestigationGoalActionEntry { slug?: string; label?: string }
interface InvestigationTimelineEntry { ts?: string; entity_id?: string; entity_type?: string; name?: string | null; event?: string }
interface InvestigationEvidenceEntry {
  opencti_id?: string | null;
  entity_type?: string | null;
  label?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
}

export const RULE_INVESTIGATION_RUN = 'investigation-run';
export const INVESTIGATION_RUN_TITLE = 'Case Autopilot investigation';
// Engine step state of a source that answered with findings (Found); empty, degraded, error and skipped did not
const STEP_WITH_FINDINGS = 'completed';
// Ledger state of a step that produced results, before the engine states
const LEGACY_STEP_WITH_FINDINGS = 'succeeded';
const INVESTIGATION_FINDING_LABELS: Record<string, string> = { first_seen: 'first seen', last_seen: 'last seen', created: 'created' };

const humanizeSlug = (slug: string) => {
  const words = slug.replace(/[_-]+/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
};

const isStepWithFindings = (step: InvestigationStepEntry) => {
  if (step.status === STEP_WITH_FINDINGS) return true;
  return !step.source_name && step.status === LEGACY_STEP_WITH_FINDINGS;
};

const stepActionKey = (step: InvestigationStepEntry): string | null => step.action || (step.source_name ? null : step.tool || null);

const stepEndTime = (step: InvestigationStepEntry, start: number | null): number | null => {
  const end = toTimelineTime(step.completed_at);
  if (end !== null) return end;
  return start !== null && step.duration_ms && step.duration_ms > 0 ? start + step.duration_ms : null;
};

interface InvestigationActionGroup {
  key: string;
  order: number;
  start: number | null;
  end: number | null;
  findings: number;
  withFindings: boolean;
  sources: Set<string>;
  states: Set<string>;
}

// Engine step states, by the meaning they share with the seven step states of the program
const QUERYING_STATES = ['running', 'querying', 'in_progress'];
const FOUND_STATES = [STEP_WITH_FINDINGS, LEGACY_STEP_WITH_FINDINGS];
const PARTIAL_STATES = ['degraded', 'partial'];
const FAILED_STATES = ['error', 'failed', 'timeout'];
const NOTHING_FOUND_STATES = ['empty', 'no_result'];
const NOT_REACHED_STATES = ['skipped', 'cancelled'];

/**
 * State of a goal-plan action from the states of its source steps, as an engine state: still querying while a source
 * is, found only when nothing failed, partial when findings come with failures or degraded answers.
 */
export const aggregateInvestigationStepState = (states: Iterable<string>): string => {
  const all = [...states].map((state) => state.toLowerCase());
  const any = (values: string[]) => all.some((state) => values.includes(state));
  if (any(QUERYING_STATES)) return 'running';
  if (any(FOUND_STATES)) return any(FAILED_STATES) || any(PARTIAL_STATES) ? 'degraded' : STEP_WITH_FINDINGS;
  if (any(PARTIAL_STATES)) return 'degraded';
  if (any(FAILED_STATES)) return 'error';
  if (any(NOTHING_FOUND_STATES)) return 'empty';
  if (any(NOT_REACHED_STATES)) return 'skipped';
  return 'planned';
};

/** One group per goal-plan action, in the order the plan declares them, then in the order the steps reached them. */
const groupStepsByAction = (steps: InvestigationStepEntry[], actionOrder: Map<string, number>): InvestigationActionGroup[] => {
  const groups = new Map<string, InvestigationActionGroup>();
  steps.forEach((step, index) => {
    const key = stepActionKey(step);
    if (!key) return;
    const start = toTimelineTime(step.started_at);
    const end = stepEndTime(step, start);
    const group = groups.get(key) ?? {
      key,
      order: actionOrder.get(key) ?? actionOrder.size + (step.position ?? index),
      start: null,
      end: null,
      findings: 0,
      withFindings: false,
      sources: new Set<string>(),
      states: new Set<string>(),
    };
    if (step.status) group.states.add(step.status);
    if (start !== null) group.start = group.start === null ? start : Math.min(group.start, start);
    if (end !== null) group.end = group.end === null ? end : Math.max(group.end, end);
    if (isStepWithFindings(step)) {
      group.withFindings = true;
      group.findings += step.findings_count && step.findings_count > 0 ? step.findings_count : 0;
      const source = step.source_name || step.tool;
      if (source) group.sources.add(source);
    }
    groups.set(key, group);
  });
  return [...groups.values()].sort((a, b) => a.order - b.order);
};

export const investigationRunRule: TimelineRule = {
  id: RULE_INVESTIGATION_RUN,
  label: 'Case Autopilot investigation runs, the goal-plan actions they reached and the findings outside the case',
  kinds: ['investigation_step'],
  derive: (input) => {
    // Findings about elements already in scope are derived by the core rules, only the others are new
    const inScope = new Set([input.container.id, ...input.entities.map((e) => e.id), ...input.relationships.map((r) => r.id)]);
    return input.soft.investigationRuns.flatMap((run) => {
      const events: DerivedTimelineEvent[] = [];
      const markings = mergeMarkings(run.markings);
      const start = toTimelineTime(readExtraString(run, 'started_at')) ?? toTimelineTime(run.created_at);
      const end = toTimelineTime(readExtraString(run, 'completed_at'));
      const status = readExtraString(run, 'run_status') ?? readExtraString(run, 'status');
      const steps = (readExtra(run, 'steps') as InvestigationStepEntry[] | undefined) ?? [];
      const goalPlan = readExtra(run, 'goal_plan') as { actions?: InvestigationGoalActionEntry[] } | undefined;
      const planActions = Array.isArray(goalPlan?.actions) ? goalPlan.actions.filter((a) => !!a?.slug) : [];
      const actionLabels = new Map(planActions.map((a) => [a.slug as string, a.label || humanizeSlug(a.slug as string)]));
      const actionOrder = new Map(planActions.map((a, index) => [a.slug as string, index]));
      // Actions the run reached (dated) or that found something; planned and not reached actions have no time to show
      const groups = groupStepsByAction(steps, actionOrder).filter((group) => group.start !== null || group.withFindings);
      const totalFindings = groups.reduce((sum, group) => sum + group.findings, 0);
      if (start !== null) {
        const details = [
          run.name && run.name !== INVESTIGATION_RUN_TITLE ? run.name : null,
          totalFindings > 0 ? formatCount(totalFindings, 'finding', 'findings') : null,
        ].filter((d) => !!d);
        events.push({
          rule_id: RULE_INVESTIGATION_RUN,
          kind: 'investigation_step',
          lane: 'response',
          element_id: run.id,
          element_type: run.entity_type,
          event_time: iso(start),
          event_end_time: end !== null && end > start ? iso(end) : null,
          time_precision: 'exact',
          name: INVESTIGATION_RUN_TITLE,
          description: details.join(' - ') || undefined,
          markings,
          source_state: { family: 'investigation_run', state: status ?? null, run_id: run.id },
        });
      }
      // Never one event per source step: a run has up to fifty of them and they would flood the lane
      groups.forEach((group) => {
        const actionStart = group.start ?? start;
        if (actionStart === null) return;
        const sources = [...group.sources].sort();
        const details = [
          group.findings > 0 ? formatCount(group.findings, 'finding', 'findings') : null,
          sources.length > 0 ? `Sources: ${sources.join(', ')}` : null,
        ].filter((d) => !!d);
        events.push({
          rule_id: RULE_INVESTIGATION_RUN,
          kind: 'investigation_step',
          lane: 'response',
          discriminator: `${run.id}-action-${group.key}`,
          element_id: run.id,
          element_type: run.entity_type,
          event_time: iso(actionStart),
          event_end_time: group.end !== null && group.end > actionStart ? iso(group.end) : null,
          time_precision: group.start !== null ? 'exact' : 'approximate',
          name: actionLabels.get(group.key) ?? humanizeSlug(group.key),
          description: details.join(' - ') || undefined,
          markings,
          ordering_hint: group.order,
          source_state: { family: 'investigation_step', state: aggregateInvestigationStepState(group.states), run_id: run.id, step: group.key },
        });
      });
      // Findings outside the case: when the run saw the element, as the engine dated it
      const seen = new Set<string>();
      const pushFinding = (entityId: string, entityType: string | null, name: string | null, event: string, time: number | null) => {
        const discriminator = `${run.id}-finding-${entityId}-${event}`;
        if (time === null || inScope.has(entityId) || seen.has(discriminator)) return;
        seen.add(discriminator);
        events.push({
          rule_id: RULE_INVESTIGATION_RUN,
          kind: 'investigation_step',
          lane: 'evidence',
          discriminator,
          element_id: entityId,
          element_type: entityType,
          source_ids: [run.id],
          event_time: iso(time),
          time_precision: 'approximate',
          name: `${name ?? entityType ?? 'Element'} ${INVESTIGATION_FINDING_LABELS[event] ?? event}`,
          description: `Found by the ${INVESTIGATION_RUN_TITLE} ${run.name}`,
          markings,
        });
      };
      const timeline = (readExtra(run, 'timeline') as InvestigationTimelineEntry[] | undefined) ?? [];
      timeline.forEach((entry) => {
        if (!entry.event || !entry.entity_id) return;
        pushFinding(entry.entity_id, entry.entity_type ?? null, entry.name ?? null, entry.event, toTimelineTime(entry.ts));
      });
      const evidence = (readExtra(run, 'evidence') as InvestigationEvidenceEntry[] | undefined) ?? [];
      evidence.forEach((entry) => {
        if (!entry.opencti_id) return;
        pushFinding(entry.opencti_id, entry.entity_type ?? null, entry.label ?? null, 'first_seen', toTimelineTime(entry.first_seen));
        pushFinding(entry.opencti_id, entry.entity_type ?? null, entry.label ?? null, 'last_seen', toTimelineTime(entry.last_seen));
      });
      return events;
    });
  },
};
// endregion

// region registry
export const TIMELINE_CORE_RULES: TimelineRule[] = [
  techniqueRule,
  observedDataRule,
  sightingRule,
  entitySeenRule,
  indicatorRule,
  reportRule,
  externalReferenceRule,
  fileRule,
  caseOpenedRule,
  taskRule,
  workflowRule,
  assignmentRule,
  noteRule,
  opinionRule,
  objectAddedRule,
  relationCreatedRule,
  mergeRule,
];

export const TIMELINE_SOFT_RULES: TimelineRule[] = [
  coverageResultRule,
  huntRunRule,
  deploymentRule,
  investigationRunRule,
];

/** Run every available rule; a failing rule never prevents the others from producing their events. */
export const deriveTimelineEvents = (
  input: TimelineDerivationInput,
  rules: TimelineRule[],
  onRuleError: (ruleId: string, error: unknown) => void,
): DerivedTimelineEvent[] => {
  const events: DerivedTimelineEvent[] = [];
  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index];
    if (!rule.isAvailable || rule.isAvailable()) {
      try {
        events.push(...rule.derive(input));
      } catch (error) {
        onRuleError(rule.id, error);
      }
    }
  }
  return events;
};
// endregion
