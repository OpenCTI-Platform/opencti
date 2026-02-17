import type { Operation } from 'fast-json-patch';
import type { StixCoreObject } from './stix-2-1-common';
import type { UserOrigin } from './user';
import type { StoreRelation } from './store';

interface CommitContext {
  message: string;
  external_references: Array<string>;
}

interface EventOpts {
  publishStreamEvent?: boolean;
}

interface CreateEventOpts extends EventOpts {
  withoutMessage?: boolean;
  restore?: boolean;
}

interface UpdateEventOpts extends EventOpts {
  commit?: CommitContext | undefined;
  related_restrictions?: { markings: string[] };
  pir_ids?: string[];
  allow_only_modified?: boolean;
  noHistory?: boolean;
}

interface RelationCreation {
  element: StoreRelation;
  event: BaseEvent | undefined;
  isCreation: boolean;
}

// stream
interface BaseEvent {
  type: string;
  version: string;
}

interface StreamNotifEvent extends BaseEvent {
  notification_id: string;
  type: 'live' | 'digest' | 'action';
}

export type StreamDataEventType = 'update' | 'create' | 'delete';

interface StreamDataEvent extends BaseEvent {
  scope: 'internal' | 'external';
  type: StreamDataEventType;
  origin: Partial<UserOrigin>;
  message: string;
  data: StixCoreObject;
  noHistory?: boolean;
}

interface Change {
  field: string;
  previous?: Array<string> | null;
  new?: Array<string> | null;
  added?: Array<string>;
  removed?: Array<string>;
}

interface UpdateEvent extends StreamDataEvent {
  type: 'update';
  commit: CommitContext | undefined;
  context: {
    patch: Array<Operation>;
    reverse_patch: Array<Operation>;
    related_restrictions?: { markings: string[] };
    pir_ids?: string[];
    changes: Change[];
  };
}

interface DeleteEvent extends StreamDataEvent {
  type: 'delete';
}

interface MergeEvent extends StreamDataEvent {
  type: 'merge';
  context: {
    patch: Array<Operation>;
    reverse_patch: Array<Operation>;
    sources: Array<StixCoreObject>;
  };
}

export interface SseEvent<T extends BaseEvent> {
  id: string;
  event: string;
  data: T;
}

type DataEvent = UpdateEvent | DataEvent | MergeEvent;

export interface ActivityStreamEvent {
  version: string;
  type: 'authentication' | 'read' | 'mutation' | 'file' | 'command';
  event_access: 'extended' | 'administration';
  prevent_indexing: boolean;
  event_scope: string;
  message: string;
  status: 'error' | 'success';
  origin: Partial<UserOrigin>;
  data: Partial<{ id: string; object_marking_refs_ids?: string[]; granted_refs_ids?: string[]; marking_definitions?: string[] }>;
}
