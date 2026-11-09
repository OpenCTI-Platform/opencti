import { describe, expect, it } from 'vitest';
import { createReleaseScheduler, type ReleaseHooks, type ScheduledMessage, type ScheduledNode, type SchedulerDeps } from '../../../src/intake/workerless/release-scheduler';

// Oracle for the head-index ready queue: the scheduler as of b48f3c0250 (Array.shift), copied
// below (comments dropped), and the current one are driven in lockstep by the same random
// events; every release and every stats() snapshot must match.

// ---- reference: createReleaseScheduler before the rewrite ----
type State = 'waiting' | 'ready' | 'released' | 'queued' | 'settled';

interface Operation {
  message: Admitted;
  index: number;
  node: ScheduledNode;
  state: State;
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

const createReleaseSchedulerOld = (deps: SchedulerDeps) => {
  let seq = 0;
  let inPreLoop = 0;
  const ready = new Map<string, Operation[]>();
  const ring: string[] = [];
  let ringIndex = 0;
  const quantum = Math.max(1, deps.quantum ?? 1);
  let served = 0;
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
    if (ring.length === 0) return undefined;
    ringIndex %= ring.length;
    const source = ring[ringIndex];
    const queue = ready.get(source) as Operation[];
    const operation = queue.shift() as Operation;
    served += 1;
    if (queue.length === 0) {
      ready.delete(source);
      ring.splice(ringIndex, 1);
      served = 0;
    } else if (served >= quantum) {
      ringIndex += 1;
      served = 0;
    }
    return operation;
  };

  const readyDepth = () => deps.queueDepth() + inPreLoop;

  // eslint-disable-next-line prefer-const
  let pump: () => void;

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
    admitted.operations.forEach((operation) => operation.node.creates.forEach((id) => {
      if (!inFlight.has(id)) inFlight.set(id, operation);
    }));
    admitted.operations.filter((operation) => operation.pending === 0).forEach(pushReady);
    pump();
  });

  return {
    admit,
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

const flush = () => new Promise((resolve) => {
  setImmediate(resolve);
});

const lcg = (seed: number) => {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
};

type Scheduler = { admit: <T>(message: ScheduledMessage<T>) => Promise<T[]>; notify: () => void; stats: () => Record<string, number> };

// One scheduler under a hand-driven fake sequencer (same shape as release-scheduler-test)
const harness = (create: (deps: SchedulerDeps) => Scheduler, deps: SchedulerDeps) => {
  const scheduler = create(deps);
  const started: string[] = [];
  const answers: string[] = [];
  const controls = new Map<string, { hooks: ReleaseHooks; settle: (result: string) => void }>();
  return {
    scheduler,
    started,
    answers,
    admit: (name: string, source: string, lane: string, nodes: ScheduledNode[]) => {
      void scheduler.admit({
        source,
        lane,
        nodes,
        run: (index: number, hooks: ReleaseHooks) => new Promise<string>((resolve) => {
          const key = `${name}:${index}`;
          started.push(key);
          controls.set(key, { hooks, settle: resolve });
        }),
      }).then((results) => answers.push(`${name}=${results.join(',')}`));
    },
    queue: (key: string) => controls.get(key)?.hooks.queued(),
    settle: (key: string) => {
      controls.get(key)?.settle(key);
      controls.delete(key);
    },
  };
};

// Random lockstep run: admissions (some deep, from few sources), queued/settled answers in
// random order, set point and queue depth moves
const lockstep = async (seed: number, steps: number) => {
  const rnd = lcg(seed);
  let depth = 0;
  let setPoint = 1 + Math.floor(rnd() * 40);
  const quantum = 1 + Math.floor(rnd() * 4);
  const deps: SchedulerDeps = { queueDepth: () => depth, setPoint: () => setPoint, quantum };
  const oldH = harness(createReleaseSchedulerOld as unknown as (d: SchedulerDeps) => Scheduler, deps);
  const newH = harness(createReleaseScheduler as unknown as (d: SchedulerDeps) => Scheduler, deps);
  const both = [oldH, newH];
  const live: string[] = [];
  let seen = 0;
  let messages = 0;
  const snapshots: { old: unknown; new: unknown }[] = [];
  for (let step = 0; step < steps; step += 1) {
    const r = rnd();
    if (r < 0.25) {
      messages += 1;
      const deep = rnd() < 0.1;
      const size = deep ? 1500 + Math.floor(rnd() * 2500) : 1 + Math.floor(rnd() * 8);
      const nodes: ScheduledNode[] = Array.from({ length: size }, (_, i) => ({
        kind: rnd() < 0.2 ? 'direct' : 'sequenced',
        deps: !deep && i > 0 && rnd() < 0.4 ? [Math.floor(rnd() * i)] : [],
        creates: rnd() < 0.3 ? [`id-${Math.floor(rnd() * 30)}`] : [],
        external: rnd() < 0.3 ? [`id-${Math.floor(rnd() * 30)}`] : [],
        answerNeeded: rnd() < 0.1,
      }));
      const source = `s${Math.floor(rnd() * 3)}`;
      const lane = rnd() < 0.8 ? 'w' : 'w2';
      both.forEach((h) => h.admit(`m${messages}`, source, lane, nodes));
    } else if (r < 0.55 && live.length > 0) {
      const key = live[Math.floor(rnd() * live.length)];
      both.forEach((h) => h.queue(key));
    } else if (r < 0.9 && live.length > 0) {
      const at = Math.floor(rnd() * live.length);
      const key = live[at];
      live.splice(at, 1);
      both.forEach((h) => h.settle(key));
    } else if (r < 0.95) {
      setPoint = Math.floor(rnd() * 60);
      both.forEach((h) => h.scheduler.notify());
    } else {
      depth = Math.floor(rnd() * 30);
      both.forEach((h) => h.scheduler.notify());
    }
    await flush();
    live.push(...oldH.started.slice(seen));
    seen = oldH.started.length;
    snapshots.push({ old: [oldH.started.length, oldH.scheduler.stats()], new: [newH.started.length, newH.scheduler.stats()] });
  }
  // drain: open the set point, settle everything still running
  setPoint = 1e9;
  depth = 0;
  both.forEach((h) => h.scheduler.notify());
  await flush();
  for (;;) {
    live.push(...oldH.started.slice(seen));
    seen = oldH.started.length;
    if (live.length === 0) break;
    const key = live.shift() as string;
    both.forEach((h) => h.settle(key));
    await flush();
  }
  return { oldH, newH, snapshots };
};

describe('Release scheduler oracle (head-index ready queue)', () => {
  it('should release in the same order and report the same stats as the Array.shift version', async () => {
    let deepestReady = 0;
    for (let seed = 1; seed <= 40; seed += 1) {
      const { oldH, newH, snapshots } = await lockstep(seed, 150);
      expect(newH.started, `seed ${seed}`).toEqual(oldH.started);
      expect(newH.answers, `seed ${seed}`).toEqual(oldH.answers);
      snapshots.forEach((s) => expect(s.new, `seed ${seed}`).toEqual(s.old));
      snapshots.forEach((s) => {
        deepestReady = Math.max(deepestReady, (s.old as any)[1].ready);
      });
    }
    // deep enough to exercise the compaction of the consumed prefix (past 1024)
    expect(deepestReady).toBeGreaterThan(3000);
  }, 60000);

  it('should drain a single deep source in admission order across compactions', async () => {
    const deps: SchedulerDeps = { queueDepth: () => 0, setPoint: () => 1 };
    const h = harness(createReleaseScheduler as unknown as (d: SchedulerDeps) => Scheduler, deps);
    const size = 5000;
    h.admit('m', 'a', 'w', Array.from({ length: size }, () => ({ kind: 'sequenced', deps: [], creates: [], external: [] })));
    await flush();
    expect(h.started).toEqual(['m:0']);
    expect(h.scheduler.stats().ready).toBe(size - 1);
    // each settle frees one slot: the next one in order is released
    for (let i = 0; i < size; i += 1) {
      h.settle(`m:${i}`);
      await flush();
      expect(h.scheduler.stats().ready).toBe(Math.max(0, size - 2 - i));
    }
    expect(h.started).toEqual(Array.from({ length: size }, (_, i) => `m:${i}`));
    expect(h.answers.length).toBe(1);
  }, 60000);
});
