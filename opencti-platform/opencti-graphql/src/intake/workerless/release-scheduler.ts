// The release scheduler of the worker-less intake (KB note opencti-workerless-intake-target-design
// §4.2-4.3). A push message is admitted as its operation graph; each operation is RELEASED (starts
// its execution) once what it depends on allows it, and only while the sequencer's ready depth is
// below its set point.
//
// Dependencies. An operation waits for each operation it depends on to be:
// - QUEUED (its intent in the sequencer queue, or settled without reaching it) when it is a
//   sequenced creation and the producer needs no answer: the sequencer queue is FIFO per source,
//   so the producer is in the same batch (a planner edge) or an earlier one, never behind;
// - SETTLED (written, failed or retained) when it is a direct operation (it reads or writes its
//   targets outside the sequencer) or when the producer's answer is needed (a producer whose id is
//   substituted once it ran).
// Dependencies come from the message's graph, and across messages from the in-flight index: an id
// the message references but does not create, created by a message admitted earlier and not yet
// settled there. Admission order is total, so the cross edges never form a cycle. The sequencer
// queue is FIFO per SOURCE (the writer's applicant) and round-robin across sources: queued is
// enough across messages only when both write as the same source, else the producer of the other
// source could be cut into a later batch than its consumer, so it must be settled.
//
// Set point. The ready depth R is the intents queued in the sequencer plus the operations released
// and not yet queued. The sequencer cuts its batch from its queue: R at max_batch keeps the batches
// full, more only adds latency (Little: R / throughput) and memory. Ready operations are released
// while R < R*, one source after the other (round-robin, the sequencer queue's own fairness; to
// compare later with favouring one source's objects together, KB note D9).

import type { OperationKind } from './operation-graph';

export interface ScheduledNode {
  kind: OperationKind;
  // Operations of the same message it depends on (earlier indexes)
  deps: number[];
  // The ids it creates, offered to the operations of later messages
  creates: string[];
  // The ids it references and its message does not create
  external: string[];
  // Its dependents need it SETTLED whatever their kind (its answer is substituted into them)
  answerNeeded?: boolean;
}

export interface ReleaseHooks {
  // The operation's intent is in the sequencer queue
  queued: () => void;
}

export interface ScheduledMessage<T> {
  // The release round-robin key
  source: string;
  // The sequencer source its intents queue under (intentSourceOf its writer)
  lane: string;
  nodes: ScheduledNode[];
  // Runs one operation to its end; calls hooks.queued when its intent is queued
  run: (index: number, hooks: ReleaseHooks) => Promise<T>;
}

export interface SchedulerDeps {
  // Intents in the sequencer queue
  queueDepth: () => number;
  // R*, the ready depth to hold
  setPoint: () => number;
}

type State = 'waiting' | 'ready' | 'released' | 'queued' | 'settled';

interface Operation {
  message: Admitted;
  index: number;
  node: ScheduledNode;
  state: State;
  // Operations it still waits for, with what it needs from each
  pending: number;
  dependents: { operation: Operation; settled: boolean }[];
}

interface Admitted {
  seq: number;
  source: string;
  lane: string;
  operations: Operation[];
  run: (index: number, hooks: ReleaseHooks) => Promise<unknown>;
  results: unknown[];
  remaining: number;
  done: (results: unknown[]) => void;
  fail: (error: unknown) => void;
}

export const createReleaseScheduler = (deps: SchedulerDeps) => {
  let seq = 0;
  // Released, not yet queued nor settled: counted in the ready depth
  let inPreLoop = 0;
  // Ready operations per source, in readiness order; sources served round-robin
  const ready = new Map<string, Operation[]>();
  let ring: string[] = [];
  let ringIndex = 0;
  // In-flight index: id -> the operation of an earlier message creating it, until it settles
  const inFlight = new Map<string, Operation>();
  let waiting = 0;
  let pumping = false;

  const reached = (operation: Operation, settled: boolean) => (settled ? operation.state === 'settled' : operation.state === 'queued' || operation.state === 'settled');

  const pushReady = (operation: Operation) => {
    operation.state = 'ready';
    waiting -= 1;
    const queue = ready.get(operation.message.source);
    if (queue) {
      queue.push(operation);
    } else {
      ready.set(operation.message.source, [operation]);
      ring.push(operation.message.source);
    }
  };

  const nextReady = (): Operation | undefined => {
    for (let tries = 0; tries < ring.length; tries += 1) {
      ringIndex %= ring.length;
      const source = ring[ringIndex];
      const queue = ready.get(source) as Operation[];
      ringIndex += 1;
      const operation = queue.shift();
      if (queue.length === 0) {
        ready.delete(source);
        ring = ring.filter((name) => name !== source);
        ringIndex -= 1;
      }
      if (operation) return operation;
    }
    return undefined;
  };

  const readyDepth = () => deps.queueDepth() + inPreLoop;

  // eslint-disable-next-line prefer-const
  let pump: () => void;

  // A state an operation reached: its dependents waiting for that state may become ready
  const advance = (operation: Operation) => {
    operation.dependents.forEach((dependent) => {
      if (dependent.operation.state !== 'waiting' || !reached(operation, dependent.settled)) return;
      dependent.operation.pending -= 1;
      if (dependent.operation.pending === 0) pushReady(dependent.operation);
    });
    operation.dependents = operation.dependents.filter((dependent) => dependent.operation.state === 'waiting');
  };

  const onQueued = (operation: Operation) => {
    if (operation.state !== 'released') return;
    operation.state = 'queued';
    inPreLoop -= 1;
    advance(operation);
    pump();
  };

  const onSettled = (operation: Operation, result: unknown) => {
    if (operation.state === 'released') inPreLoop -= 1;
    operation.state = 'settled';
    operation.node.creates.forEach((id) => {
      if (inFlight.get(id) === operation) inFlight.delete(id);
    });
    advance(operation);
    const { message } = operation;
    message.results[operation.index] = result;
    message.remaining -= 1;
    if (message.remaining === 0) message.done(message.results);
    pump();
  };

  const release = (operation: Operation) => {
    operation.state = 'released';
    inPreLoop += 1;
    let run: Promise<unknown>;
    try {
      run = operation.message.run(operation.index, { queued: () => onQueued(operation) });
    } catch (error) {
      run = Promise.reject(error);
    }
    run.then(
      (result) => onSettled(operation, result),
      (error) => {
        // run settles every operation itself (outcome, never a throw): a throw is a defect
        onSettled(operation, undefined);
        operation.message.fail(error);
      },
    );
  };

  pump = () => {
    if (pumping) return;
    pumping = true;
    try {
      const setPoint = deps.setPoint();
      while (readyDepth() < setPoint) {
        const operation = nextReady();
        if (!operation) break;
        release(operation);
      }
    } finally {
      pumping = false;
    }
  };

  const admit = <T>(message: ScheduledMessage<T>): Promise<T[]> => new Promise<T[]>((resolve, reject) => {
    seq += 1;
    const admitted: Admitted = {
      seq,
      source: message.source,
      lane: message.lane,
      operations: [],
      run: message.run,
      results: new Array(message.nodes.length),
      remaining: message.nodes.length,
      done: (results) => resolve(results as T[]),
      fail: reject,
    };
    if (message.nodes.length === 0) {
      resolve([]);
      return;
    }
    admitted.operations = message.nodes.map((node, index) => ({ message: admitted, index, node, state: 'waiting' as State, pending: 0, dependents: [] }));
    waiting += admitted.operations.length;
    admitted.operations.forEach((operation) => {
      const settledFor = (producer: Operation) => operation.node.kind === 'direct' || !!producer.node.answerNeeded || producer.message.lane !== admitted.lane;
      const producers = new Map<Operation, boolean>();
      operation.node.deps.forEach((dep) => producers.set(admitted.operations[dep], settledFor(admitted.operations[dep])));
      operation.node.external.forEach((id) => {
        const producer = inFlight.get(id);
        if (producer && producer.message !== admitted) producers.set(producer, settledFor(producer));
      });
      producers.forEach((settled, producer) => {
        if (reached(producer, settled)) return;
        operation.pending += 1;
        producer.dependents.push({ operation, settled });
      });
    });
    // offered to later messages once its own edges are built (a message never waits on itself)
    admitted.operations.forEach((operation) => operation.node.creates.forEach((id) => {
      if (!inFlight.has(id)) inFlight.set(id, operation);
    }));
    admitted.operations.filter((operation) => operation.pending === 0).forEach(pushReady);
    pump();
  });

  return {
    admit,
    // The sequencer took intents from its queue: room to release more
    notify: () => pump(),
    stats: () => ({
      waiting,
      ready: [...ready.values()].reduce((total, queue) => total + queue.length, 0),
      pre_loop: inPreLoop,
      ready_depth: readyDepth(),
      set_point: deps.setPoint(),
    }),
  };
};

export type ReleaseScheduler = ReturnType<typeof createReleaseScheduler>;
