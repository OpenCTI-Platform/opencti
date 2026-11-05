import { type DryMessageResult, emptyResult } from './dry-intake-message';

// The handling loop of the dry intake, apart from the broker so it can be tested without one:
// deliveries are handled one at a time, in order of arrival, yielding to the event loop between
// them, and each is answered (ack or nack) once, on the channel it came on.

// What the loop needs of a broker channel
export interface DryChannel<M> {
  ack: (message: M) => void;
  nack: (message: M, allUpTo?: boolean, requeue?: boolean) => void;
}

// acked or nacked: the answer was sent; dropped: the channel closed before the answer, the broker
// redelivers the message (it must not be counted twice)
export type DryAnswer = 'acked' | 'nacked' | 'dropped';

export interface DryDrainHooks<M> {
  body: (message: M) => string;
  handle: (body: string) => Promise<DryMessageResult>;
  isOpen: (channel: DryChannel<M>) => boolean;
  stopping: () => boolean;
  // Before the handling of each message
  onStart: () => void;
  // After the answer to each message
  onAnswer: (result: DryMessageResult, answer: DryAnswer, channel: DryChannel<M>) => void;
  // A hook, a handling or an answer that threw: the message is answered once and the loop goes on
  onError: (cause: unknown) => void;
}

export const createDryDrain = <M>(hooks: DryDrainHooks<M>) => {
  const pending: { message: M; channel: DryChannel<M> }[] = [];
  let draining = false;
  // The error hook failing too must not leave a delivery unanswered: nothing more to report to
  const report = (cause: unknown) => {
    try {
      hooks.onError(cause);
    } catch {
      // Ignored on purpose
    }
  };

  const answer = (message: M, channel: DryChannel<M>, result: DryMessageResult): DryAnswer => {
    if (!hooks.isOpen(channel)) {
      return 'dropped';
    }
    try {
      if (result.ack) {
        channel.ack(message);
        return 'acked';
      }
      channel.nack(message, false, false);
      return 'nacked';
    } catch (cause) {
      // A channel closing: its close event drops what it still holds, the broker redelivers
      report(cause);
      return 'dropped';
    }
  };

  const drain = async (): Promise<void> => {
    if (draining) {
      return;
    }
    draining = true;
    try {
      while (pending.length > 0 && !hooks.stopping()) {
        const { message, channel } = pending.shift() as (typeof pending)[number];
        let result: DryMessageResult;
        try {
          hooks.onStart();
          result = await hooks.handle(hooks.body(message));
        } catch (cause) {
          // Not an outcome of the transformation (processDryMessage catches those): a defect, nacked
          // as the worker nacks an unmanaged exception (push_handler.py:271-275)
          report(cause);
          result = { ...emptyResult(), ack: false, defect: true };
        }
        const answered = answer(message, channel, result);
        try {
          hooks.onAnswer(result, answered, channel);
        } catch (cause) {
          report(cause);
        }
        await new Promise((resolve) => {
          setImmediate(resolve);
        });
      }
    } finally {
      draining = false;
      // Whatever ended the loop, a message left pending is not waiting for a new delivery
      if (pending.length > 0 && !hooks.stopping()) {
        setImmediate(() => {
          drain().catch(report);
        });
      }
    }
  };

  return {
    push: (message: M, channel: DryChannel<M>) => {
      pending.push({ message, channel });
      return drain();
    },
    // The broker redelivers the unhandled messages of a closed channel: forget them, and say how many.
    // Compacted in place: a spread of the kept ones would pass them as arguments, beyond the engine's
    // limit with large prefetches (queues x prefetch, up to 65535 each)
    forget: (channel: DryChannel<M>) => {
      let kept = 0;
      for (let index = 0; index < pending.length; index += 1) {
        if (pending[index].channel !== channel) {
          pending[kept] = pending[index];
          kept += 1;
        }
      }
      const forgotten = pending.length - kept;
      pending.length = kept;
      return forgotten;
    },
    pending: () => pending.length,
  };
};
