import type { UserOrigin } from './user';
import type { StixObject } from './general';

interface EventCommit {
  message?: string;
  references: array<string>;
}

interface Event {
  version: string;
  type: string;
  origin: UserOrigin;
  markings?: Array<string>;
  message?: string;
  commit: EventCommit;
  data: StixObject;
}
