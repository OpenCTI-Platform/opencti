// POC ingestion sequencer (plan 0009, Stage B). Intent shape: one intercepted create mutation,
// carried with everything needed to apply it later through the unchanged direct path. The apply
// closure is built at the boundary (middleware.ts) so this module never imports middleware:
// no import cycle. candidateIds are best-effort at intake (cheap, no ES): for core relationships
// and sightings the full set only exists once endpoints are resolved (Stage C/D), and for
// ref/internal relationships identity is (from, to, type, window), never an id.
import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StrippedRef } from './sequencer-strip-sink';

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
  referencedIds: string[];
  // P1/option B (plan 0009 s9.8.3, suffix transport): the referenced ids this object's
  // bundle DECLARED as travelling with it (||M|| marks, stripped and collected at the
  // boundary). Undefined on non-annotated traffic: every missing ref then classifies as
  // external, exactly today's behavior.
  memberRefIds?: Set<string>;
  // s9.8.2 bounded wait: plan passes spent waiting for a declared member ref not yet seen
  // in the queue (mutated by the planner; at the limit the ref is declared dead)
  memberWaitAttempts?: number;
  // task 0040 contention diag: cycles this intent was planned then carried to the next batch
  // (multi_writer re-check conflict, batch lock retry, apply-time lock refusal)
  replans?: number;
  // s9.9 bounded wait: batches this intent was skipped in because its in-batch producer
  // failed at apply (mutated by the loop; at the limit it applies through today's path)
  failedProducerDefers?: number;
  // B10 wait TTL expiries of this intent across its re-deferrals (mutated by the lanes; at
  // the limit the intent applies as-is through today's path)
  deferredWaitExpiries?: number;
  // verdict 31 fix: refs removed by the plan-time member-dead soft strip (s9.10.2),
  // with the input key they were removed from. Harvested by applyGroup after a
  // successful apply into the pending-refs store (s9.12.3): a "dead" member is usually
  // just LATE, and the reconcile restores the edge when it lands.
  deadStrippedRefs?: { inputKey: string; refId: string }[];
  // task 0040 multi_writer step 2: keys an apply-time lock site could not take at once (held by
  // another platform): the next batch locks them up front, before it holds anything
  extraLockKeys?: string[];
  // stripSink: the loop's per-apply sink, set on the applying context (sequencer-strip-sink.ts);
  // noopSink: the elements the apply upserted without change, by internal id (sequencer-noop-memo.ts)
  apply: (stripSink?: StrippedRef[], noopSink?: Map<string, object>) => Promise<any>;
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
  referencedIds?: string[];
  memberRefIds?: Set<string>;
  apply: (stripSink?: StrippedRef[], noopSink?: Map<string, object>) => Promise<any>;
}

const intentSize = (input: Record<string, any>) => {
  try {
    return Buffer.byteLength(JSON.stringify(input));
  } catch {
    return 1024; // non-serializable input: count a nominal size, the direct path will decide
  }
};

// The source of a writer's intents: the queue is FIFO per source and round-robin across sources
export const intentSourceOf = (user: AuthUser) => user.origin?.applicant_id ?? user.id;

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
    source: intentSourceOf(args.user),
    sizeBytes: intentSize(args.input),
    candidateIds: args.candidateIds,
    referencedIds: args.referencedIds ?? [],
    memberRefIds: args.memberRefIds,
    apply: args.apply,
    resolve,
    reject,
    promise,
  };
};

// Own identity vs endpoint references (2026-09-21). A relation's candidateIds carry its
// endpoints (fromId, toId: cheap intake candidates, plan B2), which is right for lock keys
// and pre-resolution but wrong wherever "who produces id X" is asked: a relation is never
// the producer of its endpoints, and its endpoints are dependencies, not own ids.
export const intentEndpointIds = (intent: SequencerIntent): string[] => {
  if (intent.kind !== 'relation') return [];
  return [intent.input.fromId, intent.input.toId].filter((id): id is string => typeof id === 'string' && id.length > 0);
};

export const intentOwnIds = (intent: SequencerIntent): string[] => {
  const endpoints = new Set(intentEndpointIds(intent));
  return endpoints.size === 0 ? intent.candidateIds : intent.candidateIds.filter((id) => !endpoints.has(id));
};
