import { AsyncLocalStorage } from 'node:async_hooks';
import { describe, expect, it } from 'vitest';
import { runBounded } from '../../../src/database/sequencer/sequencer-apply-levels';
import { sequencerScopedContext } from '../../../src/database/sequencer/sequencer-eligibility';
import { stripSinkOf, type StrippedRef } from '../../../src/database/sequencer/sequencer-strip-sink';
import type { AuthContext } from '../../../src/types/user';

// The strip sink on the applying context: the loop's array, passed to leader.apply(sink), must
// reach every context middleware sees during that apply (spread copies, nested re-entrant creates,
// a re-scope), while 8 applies run at once (apply_concurrency 8). Oracle: the AsyncLocalStorage
// version as of b48f3c0250, copied below, collects the same strips in the same sinks.

// ---- reference: the AsyncLocalStorage sink and the scoped context before the rewrite ----
const stripSinkStorage = new AsyncLocalStorage<StrippedRef[]>();
const withStripSinkOld = <T>(sink: StrippedRef[], fn: () => Promise<T>): Promise<T> => stripSinkStorage.run(sink, fn);
const getCurrentStripSinkOld = (): StrippedRef[] | null => stripSinkStorage.getStore() ?? null;
const scopedContextOld = (context: AuthContext, scope: 'applying' | 'bypass'): AuthContext => {
  if (scope === 'applying') return { ...context, sequencer: { scope, resolutions: {} as any } };
  return { ...context, sequencer: { scope } };
};

const sleep = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

const lcg = (seed: number) => {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
};

interface Variant {
  // middleware inputResolveRefs: the sink it pushes into, read from its context
  sinkOf: (context: AuthContext) => StrippedRef[] | null;
  scoped: (context: AuthContext, scope: 'applying' | 'bypass') => AuthContext;
  // the loop: run one leader's apply with its sink
  applyWith: (sink: StrippedRef[], apply: (sink: StrippedRef[]) => Promise<void>) => Promise<void>;
  // the boundary's apply closure
  applyClosure: (submitContext: AuthContext, run: (context: AuthContext) => Promise<void>) => (sink?: StrippedRef[]) => Promise<void>;
}

const current: Variant = {
  sinkOf: (context) => stripSinkOf(context),
  scoped: (context, scope) => sequencerScopedContext(context, scope),
  applyWith: (sink, apply) => apply(sink),
  applyClosure: (submitContext, run) => (sink) => run(sequencerScopedContext(submitContext, 'applying', sink)),
};

const old: Variant = {
  sinkOf: (context) => ((context as any).sequencer?.scope === 'applying' ? getCurrentStripSinkOld() : null),
  scoped: scopedContextOld,
  applyWith: (sink, apply) => withStripSinkOld(sink, () => apply(sink)),
  applyClosure: (submitContext, run) => () => run(scopedContextOld(submitContext, 'applying')),
};

// One batch of 8 concurrent applies, the shape of a real apply: awaits, spread copies of the
// context, a nested re-entrant create (direct, under the same context), a re-scope to applying,
// a bypass scope (no strip there, as today), and an unrelated context outside the apply
const runBatch = async (variant: Variant, seed: number) => {
  const rnd = lcg(seed);
  const delays = Array.from({ length: 64 }, () => Math.floor(rnd() * 4));
  let d = 0;
  const pause = () => sleep(delays[(d++) % delays.length]);
  const strip = (context: AuthContext, targetRef: string) => variant.sinkOf(context)?.push({ targetRef, relType: 'object-label' });
  const createDirect = async (context: AuthContext, name: string, depth: number): Promise<void> => {
    await pause();
    strip(context, `${name}:a`);
    const copy = { ...context, user: { id: name } } as unknown as AuthContext;
    await pause();
    strip(copy, `${name}:b`);
    if (depth > 0) {
      // re-entrant create: the boundary sees a marked context and runs direct under it
      await createDirect(copy, `${name}/nested`, depth - 1);
      await createDirect(variant.scoped(copy, 'applying'), `${name}/rescoped`, depth - 1);
      await pause();
      strip(variant.scoped(copy, 'bypass'), `${name}:bypass`);
      strip({ otp_mandatory: false } as unknown as AuthContext, `${name}:outside`);
    }
  };
  const groups = Array.from({ length: 8 }, (_, i) => ({
    name: `leader${i}`,
    apply: variant.applyClosure({ source: `submit${i}` } as unknown as AuthContext, (context) => createDirect(context, `leader${i}`, 1)),
  }));
  let inFlight = 0;
  let maxInFlight = 0;
  const sinks = await runBounded(groups, 8, async (group) => {
    const sink: StrippedRef[] = [];
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await variant.applyWith(sink, group.apply);
    inFlight -= 1;
    return sink;
  });
  return { sinks: sinks.map((sink) => sink.map((s) => s.targetRef)), maxInFlight };
};

describe('strip sink on the applying context', () => {
  it('should land each strip of 8 concurrent applies, nested creates included, in its own leader sink', async () => {
    const { sinks, maxInFlight } = await runBatch(current, 1);
    expect(maxInFlight).toBe(8);
    sinks.forEach((sink, i) => {
      const leader = `leader${i}`;
      expect(sink).toEqual([`${leader}:a`, `${leader}:b`, `${leader}/nested:a`, `${leader}/nested:b`, `${leader}/rescoped:a`, `${leader}/rescoped:b`]);
    });
  });

  it('should collect the same strips as the AsyncLocalStorage version', async () => {
    for (let seed = 1; seed <= 20; seed += 1) {
      const [expected, actual] = await Promise.all([runBatch(old, seed), runBatch(current, seed)]);
      expect(actual.sinks, `seed ${seed}`).toEqual(expected.sinks);
    }
  });

  it('should give no sink outside an apply nor under a bypass scope', () => {
    const sink: StrippedRef[] = [];
    const applying = sequencerScopedContext({} as AuthContext, 'applying', sink);
    expect(stripSinkOf(applying)).toBe(sink);
    expect(stripSinkOf({ ...applying })).toBe(sink);
    expect(stripSinkOf(sequencerScopedContext(applying, 'applying'))).toBe(sink);
    expect(stripSinkOf(sequencerScopedContext(applying, 'bypass'))).toBeNull();
    expect(stripSinkOf(sequencerScopedContext({} as AuthContext, 'applying'))).toBeNull();
    expect(stripSinkOf({} as AuthContext)).toBeNull();
  });
});
