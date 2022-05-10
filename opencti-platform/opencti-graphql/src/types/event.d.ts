import type { Operation } from 'fast-json-patch';
import { StixCoreObject } from './stix-common';
import { UserOrigin } from './user';

interface CommitContext {
  message: string;
  references: Array<string>;
}

interface CreateEventOpts {
  withoutMessage?: boolean;
  publishStreamEvent?: boolean;
}

interface UpdateEventOpts {
  commit?: CommitContext | undefined,
  publishStreamEvent?: boolean;
}

interface DeleteEventOpts {
  publishStreamEvent?: boolean;
}

// stream
interface Event {
  id?: string;
  version: string;
  type: string;
  origin: Partial<UserOrigin>;
  message: string;
  data: StixCoreObject;
}

interface UpdateEvent extends Event {
  commit: CommitContext | undefined;
  context: {
    patch: Array<Operation>;
    reverse_patch: Array<Operation>;
  };
}

interface DeleteEvent extends Event {
  context: {
    deletions: Array<StixCoreObject>;
  };
}

interface MergeEvent extends Event {
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
