import type { Operation } from 'fast-json-patch';
import { StixCoreObject } from './stix-common';
import { UserOrigin } from './user';
import type { StoreRelation } from './store';

interface CommitContext {
  message: string;
  references: Array<string>;
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

interface RuleEvent {
  type: string;
  data?: any;
}

interface DependenciesDeleteEvent extends RuleEvent {
  type: 'delete-dependencies';
  ids: Array<string>;
}

// stream
interface Event extends RuleEvent {
  id?: string;
  version: string;
  type: string;
  scope: 'internal' | 'external';
  origin: Partial<UserOrigin>;
  message: string;
  data: StixCoreObject;
}

interface RelationCreation {
  element: StoreRelation;
  event: Event | undefined;
  isCreation: boolean;
}

interface UpdateEvent extends Event {
  type: 'update';
  commit: CommitContext | undefined;
  context: {
    patch: Array<Operation>;
    reverse_patch: Array<Operation>;
  };
}

interface DeleteEvent extends Event {
  type: 'delete';
  context: {
    deletions: Array<StixCoreObject>;
  };
}

interface MergeEvent extends Event {
  type: 'merge';
  context: {
    patch: Array<Operation>;
    reverse_patch: Array<Operation>;
    deletions: Array<StixCoreObject>;
    sources: Array<StixCoreObject>;
    shifts: Array<string>;
  };
}

interface StreamEvent {
  id: string;
  event: 'update' | 'create' | 'delete';
  data: Event
}
