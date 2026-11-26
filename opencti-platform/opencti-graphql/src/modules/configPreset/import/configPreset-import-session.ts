import { FunctionalError } from '../../../config/errors';
import type { ConfigImportMode } from '../../configImport/configImport-types';

// The state machine of the import session, one declarative list of transitions and a lookup, in the shape of
// WorkflowDefinition (modules/workflow/engine/workflow-definition.ts), copied and not imported: the workflow engine is
// behind another feature flag and a refused event here is a normal functional error.
// The values are the ones of the GraphQL enums. `interrupted` is derived when the session is read (chunk 5), never stored.
export const CONFIG_PRESET_IMPORT_SESSION_VERSION = 1;

// INTERRUPTED is derived when the session is read (stored as applying, but the import no longer runs), never stored
export type ConfigPresetImportSessionStatus = 'DRAFT' | 'APPLYING' | 'FINISHED' | 'INTERRUPTED';
export type ConfigPresetImportOutcome = 'COMPLETED' | 'STOPPED';
export type ConfigPresetImportResultStatus = 'CREATED' | 'OVERWRITTEN' | 'SKIPPED' | 'FAILED';
export type ConfigPresetImportSessionEvent = 'UPLOAD' | 'SAVE' | 'START_OVER' | 'START' | 'ITEM_PROCESSED' | 'FINISH' | 'ABORT' | 'BACK_TO_SELECTION' | 'CLOSE';

// The stored shape of a selection, not the GraphQL input
export interface ConfigPresetImportSelection {
  type: string;
  items: string[] | null;
  excluded_items: string[] | null;
  // The items that are not imported with OVERWRITE, the mode of each; absent for none
  item_modes?: { key: string; mode: ConfigImportMode }[] | null;
}

// One result per processed item: type is the bare family id, key the bundle id
export interface ConfigPresetImportItemResult {
  type: string;
  key: string;
  status: ConfigPresetImportResultStatus;
  reason: string | null;
  // The code of the importer behind the reason; absent in a session stored before the codes were kept
  code?: string | null;
  // The name of the item and whether the UI translates it; absent in a session stored before the names were kept: the key
  label?: string;
  translatable?: boolean;
}

export type ConfigPresetImportCounts = Record<'created' | 'overwritten' | 'skipped' | 'failed', number>;

export interface ConfigPresetImportSession {
  v: typeof CONFIG_PRESET_IMPORT_SESSION_VERSION;
  // internal_id of the Settings: a session restored on another platform is no session
  platform_id: string;
  status: ConfigPresetImportSessionStatus;
  // The pending zip
  file_id: string;
  selections: ConfigPresetImportSelection[];
  // Incremented by the front at each change of the selection: a lower revision is a stale tab
  revision: number;
  // One ISO string set by START
  started_at: string | null;
  total: number;
  results: ConfigPresetImportItemResult[];
  outcome: ConfigPresetImportOutcome | null;
  counts: ConfigPresetImportCounts | null;
  report_id: string | null;
}

// The code an importer gives to an item that is already as the bundle says: counted apart, it is not a problem
export const CONFIG_PRESET_CODE_UNCHANGED = 'unchanged';

export type ConfigPresetImportCountBucket = 'created' | 'overwritten' | 'unchanged' | 'skipped' | 'failed';
export const CONFIG_PRESET_COUNT_BUCKETS: ConfigPresetImportCountBucket[] = ['created', 'overwritten', 'unchanged', 'skipped', 'failed'];

// The count a result goes to: the items the platform had as they are are not "skipped", which reads as if they were ignored
export const configPresetResultBucket = ({ status, code }: Pick<ConfigPresetImportItemResult, 'status' | 'code'>): ConfigPresetImportCountBucket => {
  if (status === 'SKIPPED') {
    return code === CONFIG_PRESET_CODE_UNCHANGED ? 'unchanged' : 'skipped';
  }
  return status.toLowerCase() as ConfigPresetImportCountBucket;
};

// What needs a look in the result: an item that failed, or was skipped for a reason. The rest is in the counts and in the report.
export const isConfigPresetResultProblem = (result: Pick<ConfigPresetImportItemResult, 'status' | 'code'>) => {
  const bucket = configPresetResultBucket(result);
  return bucket === 'failed' || bucket === 'skipped';
};

export const CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT = 100;
export const CONFIG_PRESET_IMPORT_RECENT_LIMIT = 10;

export type ConfigPresetImportTypeCounts = Record<ConfigPresetImportCountBucket, number> & { type: string };

// What a result screen and a progress screen need of a run, whatever its number of items: the counts by type, a few items
export interface ConfigPresetImportProgress {
  processed: number;
  type_counts: ConfigPresetImportTypeCounts[];
  // The first items that failed or were skipped, in the order of processing, at most CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT
  problems: ConfigPresetImportItemResult[];
  // The last items processed
  recent: ConfigPresetImportItemResult[];
}

export const emptyConfigPresetImportProgress = (): ConfigPresetImportProgress => ({ processed: 0, type_counts: [], problems: [], recent: [] });

const addToTypeCounts = (counts: Map<string, ConfigPresetImportTypeCounts>, type: string, bucket: ConfigPresetImportCountBucket, count: number) => {
  const known = counts.get(type) ?? { type, created: 0, overwritten: 0, unchanged: 0, skipped: 0, failed: 0 };
  known[bucket] += count;
  counts.set(type, known);
};

// The progress of results that were stored inside the session (a session of a version that had no counters)
export const summarizeConfigPresetImportResults = (results: ConfigPresetImportItemResult[]): ConfigPresetImportProgress => {
  const counts = new Map<string, ConfigPresetImportTypeCounts>();
  results.forEach((result) => addToTypeCounts(counts, result.type, configPresetResultBucket(result), 1));
  return {
    processed: results.length,
    type_counts: [...counts.values()],
    problems: results.filter(isConfigPresetResultProblem).slice(0, CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT),
    recent: results.slice(-CONFIG_PRESET_IMPORT_RECENT_LIMIT),
  };
};

// The counters of a run are stored as `<type>|<bucket>` fields: the counts by type
export const toConfigPresetImportTypeCounts = (counters: Record<string, string>): ConfigPresetImportTypeCounts[] => {
  const counts = new Map<string, ConfigPresetImportTypeCounts>();
  Object.entries(counters).forEach(([field, value]) => {
    const [type, bucket] = field.split('|');
    if (CONFIG_PRESET_COUNT_BUCKETS.includes(bucket as ConfigPresetImportCountBucket)) {
      addToTypeCounts(counts, type, bucket as ConfigPresetImportCountBucket, Number(value) || 0);
    }
  });
  return [...counts.values()];
};

// The session as the API returns it: the wizard enables its buttons from the events the state accepts, and shows the progress of the run
export interface ConfigPresetImportGraphqlSession extends ConfigPresetImportSession, ConfigPresetImportProgress {
  available_events: ConfigPresetImportSessionEvent[];
}

export interface ConfigPresetImportSessionPayloads {
  UPLOAD: { platform_id: string; file_id: string };
  SAVE: { file_id: string; selections: ConfigPresetImportSelection[]; revision: number };
  START_OVER: undefined;
  START: { started_at: string; total: number; selections: ConfigPresetImportSelection[] };
  ITEM_PROCESSED: { result: ConfigPresetImportItemResult };
  FINISH: { outcome: ConfigPresetImportOutcome; counts: ConfigPresetImportCounts; report_id: string | null };
  ABORT: undefined;
  BACK_TO_SELECTION: undefined;
  CLOSE: undefined;
}

type SessionState = ConfigPresetImportSessionStatus | 'NONE';

// One entry per event, so that the payload of `apply` is typed by the event
type ConfigPresetImportTransition = {
  [E in ConfigPresetImportSessionEvent]: {
    event: E;
    from: SessionState;
    to: SessionState;
    // The next session (null: no session); a guard throws a FunctionalError
    apply: (session: ConfigPresetImportSession | null, payload: ConfigPresetImportSessionPayloads[E]) => ConfigPresetImportSession | null;
  };
}[ConfigPresetImportSessionEvent];

// A new pending zip: the selection starts empty
const newDraft = ({ platform_id, file_id }: ConfigPresetImportSessionPayloads['UPLOAD']): ConfigPresetImportSession => ({
  v: CONFIG_PRESET_IMPORT_SESSION_VERSION,
  platform_id,
  status: 'DRAFT',
  file_id,
  selections: [],
  revision: 0,
  started_at: null,
  total: 0,
  results: [],
  outcome: null,
  counts: null,
  report_id: null,
});

const save = (session: ConfigPresetImportSession | null, payload: ConfigPresetImportSessionPayloads['SAVE']) => {
  if (payload.file_id !== session!.file_id) {
    throw FunctionalError('The uploaded file no longer exists', { reason: 'file_missing' });
  }
  // A lower revision is a stale tab: ignored
  return payload.revision < session!.revision ? session : { ...session!, selections: payload.selections, revision: payload.revision };
};

const TRANSITIONS: ConfigPresetImportTransition[] = [
  { event: 'UPLOAD', from: 'NONE', to: 'DRAFT', apply: (_, payload) => newDraft(payload) },
  { event: 'UPLOAD', from: 'DRAFT', to: 'DRAFT', apply: (_, payload) => newDraft(payload) },
  { event: 'UPLOAD', from: 'FINISHED', to: 'DRAFT', apply: (_, payload) => newDraft(payload) },
  { event: 'SAVE', from: 'DRAFT', to: 'DRAFT', apply: save },
  { event: 'START_OVER', from: 'DRAFT', to: 'NONE', apply: () => null },
  { event: 'START_OVER', from: 'FINISHED', to: 'NONE', apply: () => null },
  { event: 'START_OVER', from: 'INTERRUPTED', to: 'NONE', apply: () => null },
  // The selection of the import, with the required dependencies the backend added, replaces the saved one
  {
    event: 'START',
    from: 'DRAFT',
    to: 'APPLYING',
    apply: (session, { started_at, total, selections }) => ({ ...session!, status: 'APPLYING', started_at, total, selections, results: [] }),
  },
  // The result of an item is appended to the list of its run (applyConfigPresetImportRunEvent): the session does not change
  { event: 'ITEM_PROCESSED', from: 'APPLYING', to: 'APPLYING', apply: (session) => session },
  {
    event: 'FINISH',
    from: 'APPLYING',
    to: 'FINISHED',
    apply: (session, { outcome, counts, report_id }) => ({ ...session!, status: 'FINISHED', outcome, counts, report_id }),
  },
  // An error before the first item: back to the draft, the file and the selection are kept
  { event: 'ABORT', from: 'APPLYING', to: 'DRAFT', apply: (session) => ({ ...session!, status: 'DRAFT', started_at: null, total: 0, results: [] }) },
  // From an interrupted import: the file and the selection are kept, the progress and the item results are dropped
  { event: 'BACK_TO_SELECTION', from: 'INTERRUPTED', to: 'DRAFT', apply: (session) => ({ ...session!, status: 'DRAFT', started_at: null, total: 0, results: [] }) },
  { event: 'CLOSE', from: 'FINISHED', to: 'NONE', apply: () => null },
];

const stateOf = (session: ConfigPresetImportSession | null): SessionState => session?.status ?? 'NONE';

// The events the current state accepts, for the wizard to enable its buttons
export const getConfigPresetImportAvailableEvents = (session: ConfigPresetImportSession | null): ConfigPresetImportSessionEvent[] => {
  return [...new Set(TRANSITIONS.filter(({ from }) => from === stateOf(session)).map(({ event }) => event))];
};

// The next session (null: no session), or a FunctionalError when the current state does not accept the event
export const transitionConfigPresetImportSession = <E extends ConfigPresetImportSessionEvent>(
  session: ConfigPresetImportSession | null,
  event: E,
  payload: ConfigPresetImportSessionPayloads[E],
): ConfigPresetImportSession | null => {
  const found = TRANSITIONS.find((t) => t.event === event && t.from === stateOf(session));
  if (!found) {
    throw FunctionalError('This action is not available in the current state of the import', { event, status: stateOf(session) });
  }
  return found.apply(session, payload as never);
};
