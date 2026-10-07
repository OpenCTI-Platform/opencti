import { describe, expect, it } from 'vitest';
import { createBoundedJobQueue } from '../../../../src/modules/timeMachine/timeMachine-jobQueue';

const deferred = () => {
  let resolve: () => void = () => {};
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

describe('Bounded job queue', () => {
  it('should run at most the given number of jobs at a time', async () => {
    const queue = createBoundedJobQueue('test', 2, 10);
    const gates = [deferred(), deferred(), deferred()];
    let running = 0;
    let maxRunning = 0;
    gates.forEach((gate, index) => {
      queue.enqueue(`job-${index}`, async () => {
        running += 1;
        maxRunning = Math.max(maxRunning, running);
        await gate.promise;
        running -= 1;
      });
    });
    expect(queue.size()).toBe(3);
    gates.forEach((gate) => gate.resolve());
    await queue.idle();
    expect(maxRunning).toBe(2);
    expect(queue.size()).toBe(0);
  });

  it('should not queue a job already queued or running, and accept it again once done', async () => {
    const queue = createBoundedJobQueue('test', 1, 10);
    const gate = deferred();
    let runs = 0;
    const job = async () => {
      runs += 1;
      await gate.promise;
    };
    expect(queue.enqueue('same', job)).toBe(true);
    expect(queue.enqueue('same', job)).toBe(false);
    gate.resolve();
    await queue.idle();
    expect(queue.enqueue('same', job)).toBe(true);
    await queue.idle();
    expect(runs).toBe(2);
  });

  it('should drop the jobs beyond the pending limit and keep going after a failed job', async () => {
    const queue = createBoundedJobQueue('test', 1, 1);
    const gate = deferred();
    const done: string[] = [];
    queue.enqueue('running', async () => {
      await gate.promise;
      throw new Error('job failed');
    });
    expect(queue.enqueue('waiting', async () => {
      done.push('waiting');
    })).toBe(true);
    expect(queue.enqueue('dropped', async () => {
      done.push('dropped');
    })).toBe(false);
    gate.resolve();
    await queue.idle();
    expect(done).toEqual(['waiting']);
  });

  it('should forget the jobs that have not started when cleared and let the running ones finish', async () => {
    const queue = createBoundedJobQueue('test', 1, 10);
    const gate = deferred();
    const done: string[] = [];
    queue.enqueue('running', async () => {
      await gate.promise;
      done.push('running');
    });
    queue.enqueue('waiting', async () => {
      done.push('waiting');
    });
    queue.clear();
    expect(queue.size()).toBe(1);
    gate.resolve();
    await queue.idle();
    expect(done).toEqual(['running']);
    // A cleared job can be queued again
    expect(queue.enqueue('waiting', async () => {
      done.push('waiting');
    })).toBe(true);
    await queue.idle();
    expect(done).toEqual(['running', 'waiting']);
  });
});
