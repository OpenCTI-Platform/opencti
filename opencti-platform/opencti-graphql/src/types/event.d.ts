import type { Operation } from 'fast-json-patch';
import { StixCoreObject } from './stix-common';
import { UserOrigin } from './user';
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
}

interface UpdateEventOpts extends EventOpts {
  commit?: CommitContext | undefined;
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
  notification_id: string
  type: 'live' | 'digest';
}

interface StreamDataEvent extends BaseEvent {
  scope: 'internal' | 'external';
  type: 'update' | 'create' | 'delete';
  origin: Partial<UserOrigin>;
  message: string;
  data: StixCoreObject
}

interface UpdateEvent extends StreamDataEvent {
  type: 'update';
  commit: CommitContext | undefined;
  context: {
    patch: Array<Operation>;
    reverse_patch: Array<Operation>;
  };
}

interface DeleteEvent extends StreamDataEvent {
  type: 'delete';
  context: {
    deletions: Array<StixCoreObject>;
  };
}

interface MergeEvent extends StreamDataEvent {
  type: 'merge';
  context: {
    patch: Array<Operation>;
    reverse_patch: Array<Operation>;
    deletions: Array<StixCoreObject>;
    sources: Array<StixCoreObject>;
    shifts: Array<string>;
  };
}

interface DependenciesDeleteEvent extends BaseEvent {
  type: 'delete-dependencies';
  data: {
    ids: Array<string>
  };
}

export interface SseEvent<T extends BaseEvent> {
  id: string;
  event: string;
  data: T;
}

type DataEvent = UpdateEvent | DataEvent | MergeEvent;
