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

// The session as the API returns it: the wizard enables its buttons from the events the state accepts
export interface ConfigPresetImportGraphqlSession extends ConfigPresetImportSession {
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
  {
    event: 'ITEM_PROCESSED',
    from: 'APPLYING',
    to: 'APPLYING',
    apply: (session, { result }) => ({ ...session!, results: [...session!.results, result] }),
  },
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
