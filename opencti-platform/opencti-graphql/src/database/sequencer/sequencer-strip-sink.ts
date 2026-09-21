// s9.12.3 strip-and-reconcile: the sink into which inputResolveRefs pushes the refs it strips
// during ONE apply. Until 2026-09-21 it was a module-level slot armed around each leader.apply()
// (applies were serial). The concurrent apply within a batch (rung 5) runs several applies at
// once on the same event loop, so the slot is an AsyncLocalStorage store: each apply runs inside
// withStripSink(sink, fn) and everything awaited from it (middleware, nested re-entrant creates)
// reads its own sink through getCurrentStripSink(). A slot carried on the context does NOT work:
// the 'applying' scoped context is a spread COPY built inside the apply closure, so the loop never
// sees what middleware writes on it (first validation campaign: strips fired, zero records
// persisted, refs lost).
import { AsyncLocalStorage } from 'node:async_hooks';

export interface StrippedRef { targetRef: string; relType: string }

const stripSinkStorage = new AsyncLocalStorage<StrippedRef[]>();

export const withStripSink = <T>(sink: StrippedRef[], fn: () => Promise<T>): Promise<T> => stripSinkStorage.run(sink, fn);

export const getCurrentStripSink = (): StrippedRef[] | null => stripSinkStorage.getStore() ?? null;
