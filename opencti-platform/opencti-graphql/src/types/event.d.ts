import type { Operation } from 'fast-json-patch';
import { StixCoreObject } from './stix-common';
import { UserOrigin } from './user';

interface CommitContext {
  message: string;
  references: Array<string>;
}

interface CreateEventOpts {
  withoutMessage?: boolean;
}

interface EventContext {
  commitMessage?: string;
  references?: Array<string>;
  previous_patch?: Array<Operation> | undefined;
  deletions?: Array<StixCoreObject>;
  sources?: Array<StixCoreObject>;
  shifts?: Array<string>;
}

// stream
interface Event {
  version: string;
  type: string;
  origin: Partial<UserOrigin>;
  message: string;
  data: StixCoreObject;
}

interface UpdateEvent extends Event {
  commit: CommitContext | undefined;
  context: {
    previous_patch: Array<Operation>;
  };
}

interface DeleteEvent extends Event {
  context: {
    deletions: Array<StixCoreObject>;
  };
}

interface MergeEvent extends Event {
  context: {
    previous_patch: Array<Operation>;
    deletions: Array<StixCoreObject>;
    sources: Array<StixCoreObject>;
    shifts: Array<string>;
  };
}

interface StreamEvent {
  id: string;
  event: 'update' | 'create' | 'delete';
  data: DataEvent
}
