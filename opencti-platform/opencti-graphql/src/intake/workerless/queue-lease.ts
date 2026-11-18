import { v4 as uuidv4 } from 'uuid';

// task 0040 dynamic queue lease (multi_writer): each connector push queue is consumed by the platform
// holding its lease in Redis, so that the platforms write disjoint connectors and share fewer lock
// keys. On each tick of the manager a platform renews its leases, gives back the queues empty for
// `releaseIdleTicks` ticks, and takes the free queues holding messages, the largest first, while they fit in its
// share (total load / live platforms), beyond it when it is the least loaded platform or when a queue waited free
// for STARVING_TICKS ticks (no queue left unconsumed). The load of a queue is the bytes of its messages ready and
// unacked (a queue of giant bundles is not worth a queue of small objects).
// Rebalancing: a platform well above its share while another is well under gives back one queue at a time
// (shedding), one whose move narrows the gap, so that a new platform or the queues left after others drained are
// spread again; what shedding cannot move (one queue larger than a share) is joined, as a further consumer, by the
// platforms under half their share or left without messages ready (work stealing, one queue per platform), until
// that queue is empty; never a queue that carried events, consumed in order by its holder. A queue is shed only when the
// least loaded platform takes it by its own rule and stays the least loaded; a queue its consumer still drains (a
// message never answered) is neither taken nor stolen, so a shed can starve and be taken back by its shedder, which
// then does not shed it again for SHED_TAKEN_BACK_TICKS ticks. Without the queue
// depths (management API unreachable from this platform) it keeps its queues, decides nothing and unpublishes its
// load: the other platforms count it out at once and do the balancing.
// A lease is a hint, not a guard: two consumers on a queue is the sharing without lease, slower only. The ordered
// queues of the synchronizations stay out of it (push-queues.ts leadership). Event messages come only from
// synchronizations today, so the ordered marking below guards a future producer; a queue stolen before its first
// event is consumed twice until the stealer's next tick. A free queue marked ordered waits a TTL even after a clean
// hand-back (latency only).

// Thresholds of the rebalancing, in shares: shed above SHED_ABOVE while the least loaded is under UNDER, for
// SHED_TICKS ticks in a row; steal under STEAL_BELOW, kept under UNDER. In ticks of the manager: a queue moved
// (taken or shed) here is not moved again by this platform for MOVED_COOLDOWN_TICKS ticks, unless it waited free for
// STARVING_TICKS ticks; a queue given back whose consumer is still draining after MOVED_COOLDOWN_TICKS ticks (a message
// never answered) is released anyway: another platform consumes it beside the stuck message; a queue shed then
// taken back here is not shed again for SHED_TAKEN_BACK_TICKS ticks (the least loaded could not take it)
const SHED_ABOVE = 1.25;
const UNDER = 0.75;
const STEAL_BELOW = 0.5;
const SHED_TICKS = 3;
const MOVED_COOLDOWN_TICKS = 6;
const STARVING_TICKS = 2;
const SHED_TAKEN_BACK_TICKS = 5 * MOVED_COOLDOWN_TICKS;

export interface QueueDepth {
  ready: number;
  unacked: number;
  // bytes of the messages ready and unacked (management stats, sampled): 0 or absent while not sampled
  bytesReady?: number;
  bytesUnacked?: number;
}

export interface LeaseStore {
  // Extends the lease while held by the token, takes it back when it expired free; false when another holds it
  renew: (queue: string, token: string, ttlMs: number) => Promise<boolean>;
  acquire: (queue: string, token: string, ttlMs: number) => Promise<boolean>;
  release: (queue: string, token: string) => Promise<boolean>;
  holders: (queues: string[]) => Promise<Map<string, string | null>>;
  // its load in bytes, and in messages for the platforms of the previous version (rolling deploy)
  publishBacklog: (token: string, load: number, messages: number) => Promise<void>;
  // The load published by each live platform (self included): published within the last ttlMs; null for a live
  // platform whose load is not comparable (a previous version publishing message counts, during a rolling deploy)
  liveBacklogs: (ttlMs: number) => Promise<Map<string, number | null>>;
  // No longer live (the platform stops)
  unpublish: (token: string) => Promise<void>;
  markOrdered: (queues: string[]) => Promise<void>;
  ordered: (queues: string[]) => Promise<Set<string>>;
}

// What the platform's consumer knows of a queue
export interface ConsumerView {
  // An event message was consumed from it: its holder consumes it in order
  isOrdered: (queue: string) => boolean;
  // Its channel is open (a stopped queue is drained and closed)
  isConsuming: (queue: string) => boolean;
  // Stopped and still draining: not consumed again before its channel is closed, even if listed again
  isStopping: (queue: string) => boolean;
  // Its messages delivered here, not answered yet: with a prefetch of hundreds (push-prefetch.ts), a queue
  // whose ready messages are all delivered still has work here
  inFlight: (queue: string) => number;
}

export type LeaseEvent = 'taken' | 'released' | 'lost' | 'shed' | 'steal_start' | 'steal_stop' | 'depths_unread' | 'depths_read';
// The figures behind a decision (taken: the queue's load in bytes, the platform's own load before it, its share,
// the live platforms, whether it waited free; released: still_draining when its consumer had not stopped; shed: the
// queue's ready load, own load, share, least loaded other; steal_start: the queue's messages ready; steal_stop: taken
// when it became the stealer's own)
export type LeaseEventDetail = Record<string, number>;

export interface QueueLeaseOptions {
  ttlMs: number;
  // clock of the free-since delays (tests)
  now?: () => number;
  // Messages ready on the queue of another platform before joining it, and on a queue before shedding it
  stealBacklogMin: number;
  releaseIdleTicks: number;
  // Rebalancing: shedding, and stealing when under half a share (not only when idle)
  shed: boolean;
  stealUnderloaded: boolean;
}

export interface QueueLease {
  renew: () => Promise<void>;
  // The queues to consume among the candidates
  assign: (candidates: string[], consumer: ConsumerView) => Promise<string[]>;
  // The queues consumed without a new decision
  current: () => string[];
  // A queue whose consumer received an event message: marked at once, no other platform joins it
  markOrdered: (queue: string) => Promise<void>;
  release: () => Promise<void>;
}

// The load of the candidate queues: the bytes of their messages ready and unacked; a part (ready or unacked) with
// messages but no bytes sampled yet counts its messages at the mean size of the candidates' parts whose bytes are
// known (1 byte when none: then loads are message counts)
export const queueLoads = (depths: Map<string, QueueDepth>, candidates: string[] = [...depths.keys()]) => {
  let knownBytes = 0;
  let knownMessages = 0;
  candidates.forEach((queue) => {
    const depth = depths.get(queue);
    if (!depth) return;
    [[depth.ready, depth.bytesReady ?? 0], [depth.unacked, depth.bytesUnacked ?? 0]].forEach(([messages, bytes]) => {
      if (bytes > 0 && messages > 0) {
        knownBytes += bytes;
        knownMessages += messages;
      }
    });
  });
  const mean = knownMessages > 0 ? knownBytes / knownMessages : 1;
  const measured = (messages: number, bytes: number) => (bytes > 0 ? bytes : messages * mean);
  const readyLoad = (queue: string) => {
    const depth = depths.get(queue);
    return depth ? measured(depth.ready, depth.bytesReady ?? 0) : 0;
  };
  return {
    load: (queue: string) => {
      const depth = depths.get(queue);
      return depth ? readyLoad(queue) + measured(depth.unacked, depth.bytesUnacked ?? 0) : 0;
    },
    readyLoad,
  };
};

export const createQueueLease = (
  nodeId: string,
  store: LeaseStore,
  readDepths: () => Promise<Map<string, QueueDepth>>,
  options: QueueLeaseOptions,
  onEvent: (event: LeaseEvent, queue: string, detail?: LeaseEventDetail) => void,
): QueueLease => {
  // A restarted platform keeps its node id but never renews the leases of its previous run
  const token = `${nodeId}:${uuidv4()}`;
  const held = new Set<string>();
  // Given back once its consumer is stopped: renewed until then, so no other platform takes it while
  // its messages in flight are still written
  // the tick each was given back
  const releasing = new Map<string, number>();
  const idleTicks = new Map<string, number>();
  let stealing: string | null = null;
  let first = true;
  const now = options.now ?? Date.now;
  // A free queue marked ordered is taken once seen free for a lease TTL: its previous holder, which lost
  // or gave it back, may still answer its messages in flight, and they are consumed in order
  const freeSince = new Map<string, number>();
  // Rebalancing state: ticks of this platform, when each queue was taken or shed here, first seen free with
  // messages, the shed still draining, ticks in a row above its share, depths unread since
  let tick = 0;
  const takenAt = new Map<string, number>();
  const shedAt = new Map<string, number>();
  const takenBackAt = new Map<string, number>();
  const freeSeen = new Map<string, number>();
  let shedDraining: string | null = null;
  let overTicks = 0;
  let depthsUnread = false;
  const current = () => [...held, ...(stealing ? [stealing] : [])];
  const movedRecently = (moves: Map<string, number>, queue: string) => tick - (moves.get(queue) ?? -Infinity) < MOVED_COOLDOWN_TICKS;
  const stopSteal = (detail?: LeaseEventDetail) => {
    if (stealing) onEvent('steal_stop', stealing, detail);
    stealing = null;
  };
  const lose = (queue: string) => {
    held.delete(queue);
    releasing.delete(queue);
    idleTicks.delete(queue);
    if (shedDraining === queue) shedDraining = null;
    onEvent('lost', queue);
  };
  // Given back once their consumer is stopped, or still draining for the cooldown (a message never answered)
  const releaseDrained = async (consumer: ConsumerView) => {
    for (const [queue, since] of [...releasing]) {
      const stillDraining = consumer.isConsuming(queue);
      if (!stillDraining || tick - since >= MOVED_COOLDOWN_TICKS) {
        releasing.delete(queue);
        if (shedDraining === queue) shedDraining = null;
        await store.release(queue, token);
        onEvent('released', queue, stillDraining ? { still_draining: 1 } : undefined);
      }
    }
  };
  const giveBack = (queue: string) => {
    held.delete(queue);
    idleTicks.delete(queue);
    releasing.set(queue, tick);
  };
  // The free queues that may be taken now: not seen marked ordered, or seen free for a TTL
  const takeable = async (freeCandidates: string[]) => {
    const markedFree = freeCandidates.length > 0 ? await store.ordered(freeCandidates) : new Set<string>();
    const at = now();
    [...freeSince.keys()].filter((queue) => !markedFree.has(queue)).forEach((queue) => freeSince.delete(queue));
    markedFree.forEach((queue) => {
      if (!freeSince.has(queue)) freeSince.set(queue, at);
    });
    return freeCandidates.filter((queue) => !markedFree.has(queue) || at - (freeSince.get(queue) ?? at) >= options.ttlMs);
  };
  const acquire = async (queue: string, detail: LeaseEventDetail) => {
    if (!await store.acquire(queue, token, options.ttlMs)) return false;
    held.add(queue);
    // shed here within the cooldown: the least loaded did not take it (it starved), not shed again for a while
    if (movedRecently(shedAt, queue)) takenBackAt.set(queue, tick);
    takenAt.set(queue, tick);
    // its holder gave it back while it was stolen here: now its own, its consumer goes on
    if (stealing === queue) stopSteal({ taken: 1 });
    onEvent('taken', queue, detail);
    return true;
  };
  return {
    renew: async () => {
      for (const queue of [...held, ...releasing.keys()]) {
        if (!await store.renew(queue, token, options.ttlMs)) lose(queue);
      }
    },
    assign: async (candidates, consumer) => {
      tick += 1;
      const listed = new Set(candidates);
      let depths: Map<string, QueueDepth>;
      try {
        depths = await readDepths();
      } catch {
        // Without the depths: its leases kept (renewed), the queues no longer listed given back, nothing else
        // decided, its load unpublished (the others count it out at once and balance without it, no shed toward a
        // platform that takes nothing); the tick counts restart after the outage
        if (!depthsUnread) {
          depthsUnread = true;
          onEvent('depths_unread', '*');
          // not unpublished: counted out by the others a TTL after its last publication
          await store.unpublish(token).catch(() => {});
        }
        overTicks = 0;
        idleTicks.clear();
        freeSeen.clear();
        await releaseDrained(consumer);
        [...held].filter((queue) => !listed.has(queue)).forEach(giveBack);
        stopSteal();
        return current();
      }
      if (depthsUnread) onEvent('depths_read', '*');
      depthsUnread = false;
      const ready = (queue: string) => depths.get(queue)?.ready ?? 0;
      const messages = (queue: string) => ready(queue) + (depths.get(queue)?.unacked ?? 0);
      const { load, readyLoad } = queueLoads(depths, candidates);
      // Released: drained queues, then empty (or no longer listed) held ones
      await releaseDrained(consumer);
      for (const queue of [...held]) {
        const ticks = messages(queue) === 0 ? (idleTicks.get(queue) ?? 0) + 1 : 0;
        idleTicks.set(queue, ticks);
        if (!listed.has(queue) || ticks >= options.releaseIdleTicks) giveBack(queue);
      }
      const orderedHeld = [...held].filter(consumer.isOrdered);
      if (orderedHeld.length > 0) await store.markOrdered(orderedHeld);
      let own = [...held].reduce((sum, queue) => sum + load(queue), 0);
      const publish = () => store.publishBacklog(token, own, [...held].reduce((sum, queue) => sum + messages(queue), 0));
      // The first tick only announces the platform: the others count it in their share before it takes
      if (first) {
        first = false;
        await publish();
        return current();
      }
      const live = await store.liveBacklogs(options.ttlMs);
      live.set(token, own);
      const total = candidates.reduce((sum, queue) => sum + load(queue), 0);
      const share = total / live.size;
      const alone = live.size === 1;
      // the least loaded among the platforms whose load is known (a previous version's is not)
      const others = [...live].filter(([node, value]) => node !== token && value !== null).map(([, value]) => value as number);
      const minOther = others.length > 0 ? Math.min(...others) : Infinity;
      const leastLoaded = (ownLoad: number) => alone || (others.length > 0 && ownLoad <= minOther);
      const holders = await store.holders(candidates);
      // never a queue its consumer still drains (given back, or lost): taken back once its channel is closed (its
      // consumer would not reopen it); its stolen queue, consumed here, may be taken
      const freeCandidates = candidates.filter((queue) => !holders.get(queue) && !releasing.has(queue) && messages(queue) > 0
        && !consumer.isStopping(queue));
      [...freeSeen.keys()].filter((queue) => !freeCandidates.includes(queue)).forEach((queue) => freeSeen.delete(queue));
      freeCandidates.forEach((queue) => {
        if (!freeSeen.has(queue)) freeSeen.set(queue, tick);
      });
      const free = (await takeable(freeCandidates)).sort((a, b) => load(b) - load(a));
      for (const queue of free) {
        // A queue waiting free for a few ticks is taken by any platform, the one it shed included
        const starving = tick - (freeSeen.get(queue) ?? tick) >= STARVING_TICKS;
        // Taken when it fits in its share (overshoots it by less than half of the queue), when this platform is
        // the least loaded, or when nobody took it for a few ticks: a queue goes to the platform it fits best. Its
        // stolen queue, now free, is taken at once (already consumed here)
        const fits = own === 0 || own + load(queue) / 2 <= share;
        if (starving || queue === stealing || (!movedRecently(shedAt, queue) && (fits || leastLoaded(own)))) {
          if (await acquire(queue, { load: load(queue), own, share: Math.round(share), live: live.size, starving: starving ? 1 : 0 })) own += load(queue);
        }
      }
      // Shedding: well above its share for a few ticks while another is well under, one queue at a time, one with
      // messages ready (what moves: its unacked ones are answered here), whose move narrows the gap with the least
      // loaded (no ping-pong), that the least loaded takes by its own rule (fits its share) and after which this
      // platform stays at least as loaded (not the least loaded: it does not take it back by its own rule), the
      // closest to half of the gap; not a queue it took back after shedding it (SHED_TAKEN_BACK_TICKS)
      const over = options.shed && others.length > 0 && own > SHED_ABOVE * share && minOther < UNDER * share;
      overTicks = over ? overTicks + 1 : 0;
      if (overTicks >= SHED_TICKS && !shedDraining) {
        const gap = own - minOther;
        // never a queue marked ordered (the held ones its consumer saw carrying events were marked above)
        const movable = [...held].filter((queue) => !movedRecently(takenAt, queue) && tick - (takenBackAt.get(queue) ?? -Infinity) >= SHED_TAKEN_BACK_TICKS
          && ready(queue) >= options.stealBacklogMin && readyLoad(queue) < gap
          && minOther + readyLoad(queue) / 2 <= share && own - load(queue) >= minOther);
        const marked = movable.length > 0 ? await store.ordered(movable) : new Set<string>();
        const shed = movable.filter((queue) => !marked.has(queue)).sort((a, b) => Math.abs(readyLoad(a) - gap / 2) - Math.abs(readyLoad(b) - gap / 2))[0];
        if (shed) {
          onEvent('shed', shed, { ready_load: readyLoad(shed), own, share: Math.round(share), min_other: Math.round(minOther) });
          giveBack(shed);
          shedAt.set(shed, tick);
          shedDraining = shed;
          overTicks = 0;
          own -= load(shed);
        }
      }
      await publish();
      // Stealing: when idle (nothing ready on its queues, nothing of theirs in flight here) on any queue with
      // steal_backlog_min messages ready, or when under half its share on a queue larger than a share (what
      // shedding cannot move); kept while that queue has work here and its own queues have nothing ready or it
      // stays under UNDER x share (the same fact as the start, with a margin: no stop and start at each tick).
      // Never a queue it shed recently (it would drain then reopen its consumer), nor one its consumer still drains
      // (not reopened before its channel is closed: stolen, it would be consumed by nobody here); other platforms may
      // steal the same queue, each a further consumer
      let target: string | null = null;
      const ownReady = [...held].some((queue) => ready(queue) > 0);
      const idle = !ownReady && [...held].every((queue) => consumer.inFlight(queue) === 0);
      const underloaded = options.stealUnderloaded && !alone && own < STEAL_BELOW * share;
      const keptUnder = options.stealUnderloaded && !alone && own < UNDER * share;
      if (idle || underloaded || stealing) {
        const othersQueues = candidates.filter((queue) => !held.has(queue) && !releasing.has(queue) && !!holders.get(queue) && holders.get(queue) !== token);
        const marked = othersQueues.length > 0 ? await store.ordered(othersQueues) : new Set<string>();
        const stealable = othersQueues.filter((queue) => !marked.has(queue) && !consumer.isOrdered(queue) && !movedRecently(shedAt, queue)
          && !consumer.isStopping(queue));
        if (stealing && stealable.includes(stealing) && (ready(stealing) > 0 || consumer.inFlight(stealing) > 0) && (!ownReady || keptUnder)) {
          target = stealing;
        } else if (idle || underloaded) {
          const best = stealable
            .filter((queue) => ready(queue) >= options.stealBacklogMin && (idle || load(queue) > share))
            .sort((a, b) => readyLoad(b) - readyLoad(a))[0];
          target = best ?? null;
        }
      }
      if (target !== stealing) {
        stopSteal();
        if (target) onEvent('steal_start', target, { ready: ready(target) });
        stealing = target;
      }
      return current();
    },
    current,
    markOrdered: async (queue) => {
      await store.markOrdered([queue]);
    },
    release: async () => {
      const queues = [...held, ...releasing.keys()];
      held.clear();
      releasing.clear();
      stopSteal();
      for (const queue of queues) await store.release(queue, token);
      await store.unpublish(token);
    },
  };
};
