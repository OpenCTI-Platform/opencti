// s9.12.3 strip-and-reconcile: the sink into which inputResolveRefs pushes the refs it strips
// during ONE apply. Until 2026-09-21 it was a module-level slot armed around each leader.apply()
// (applies were serial); the concurrent apply within a batch (rung 5) then made it an
// AsyncLocalStorage store, whose run() around every apply was the only thing turning the promise
// hooks on (2.8% of the main thread, write-path CPU note Lot 1).
// The sink now travels on the context, by reference: the loop creates the array and passes it to
// leader.apply(sink); the apply closure builds its 'applying' scoped context with it
// (sequencerScopedContext), and every copy of that context (spreads, nested re-entrant creates,
// which run direct under it) shares the same context.sequencer object, so middleware pushes into
// the array the loop holds. A first attempt that wrote a slot ON the context failed (strips fired,
// zero records persisted): the scoped context is a spread COPY built inside the apply closure, the
// loop never saw it. Middleware pushes, never reassigns.
import type { AuthContext } from '../../types/user';

export interface StrippedRef { targetRef: string; relType: string }

// The sink of the apply this context runs under, null outside an apply
export const stripSinkOf = (context: AuthContext): StrippedRef[] | null => (context.sequencer?.scope === 'applying' ? context.sequencer.stripSink ?? null : null);
