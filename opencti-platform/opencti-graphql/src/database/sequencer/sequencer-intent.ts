// POC ingestion sequencer (plan 0009, Stage B). Intent shape: one intercepted create mutation,
// carried with everything needed to apply it later through the unchanged direct path. The apply
// closure is built at the boundary (middleware.ts) so this module never imports middleware:
// no import cycle. candidateIds are best-effort at intake (cheap, no ES): for core relationships
// and sightings the full set only exists once endpoints are resolved (Stage C/D), and for
// ref/internal relationships identity is (from, to, type, window), never an id.
import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';

export type IntentKind = 'entity' | 'relation';

export interface SequencerIntent {
  id: string;
  kind: IntentKind;
  type: string;
  input: Record<string, any>;
  user: AuthUser;
  context: AuthContext;
  opts: Record<string, any>;
  arrivedAt: number;
  source: string;
  sizeBytes: number;
  candidateIds: string[];
  apply: () => Promise<any>;
  resolve: (value: any) => void;
  reject: (err: any) => void;
  promise: Promise<any>;
}

interface BuildIntentArgs {
  kind: IntentKind;
  type: string;
  input: Record<string, any>;
  user: AuthUser;
  context: AuthContext;
  opts: Record<string, any>;
  candidateIds: string[];
  apply: () => Promise<any>;
}

const intentSize = (input: Record<string, any>) => {
  try {
    return Buffer.byteLength(JSON.stringify(input));
  } catch {
    return 1024; // non-serializable input: count a nominal size, the direct path will decide
  }
};

export const buildIntent = (args: BuildIntentArgs): SequencerIntent => {
  let resolve: (value: any) => void = () => {};
  let reject: (err: any) => void = () => {};
  const promise = new Promise<any>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return {
    id: uuidv4(),
    kind: args.kind,
    type: args.type,
    input: args.input,
    user: args.user,
    context: args.context,
    opts: args.opts,
    arrivedAt: Date.now(),
    source: args.user.origin?.applicant_id ?? args.user.id,
    sizeBytes: intentSize(args.input),
    candidateIds: args.candidateIds,
    apply: args.apply,
    resolve,
    reject,
    promise,
  };
};
