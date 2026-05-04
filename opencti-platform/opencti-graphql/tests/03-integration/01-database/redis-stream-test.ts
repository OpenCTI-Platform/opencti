import { describe, it, expect } from 'vitest';
import { createStreamProcessor } from '../../../src/database/stream/stream-handler';
import type { ActivityStreamEvent, SseEvent } from '../../../src/types/event';
import { wait } from '../../../src/database/utils';
import { type StreamProcessor } from '../../../src/database/stream/stream-utils';

describe('Redis stream test coverage', () => {
  it('Should stream processor works', async () => {
    const startTime = Date.now();
    let streamProcessor: StreamProcessor;
    const streamTestStart = async () => {
      console.time('Stream start');
      const streamTestHandler = async (_streamEvents: Array<SseEvent<ActivityStreamEvent>>) => {
        // Do nothing
        await wait(100);
      };
      streamProcessor = createStreamProcessor('Activity manager', streamTestHandler);
      await streamProcessor.start(undefined);
      console.timeEnd('Stream start');
    };

    const streamTestStop = async () => {
      console.time('500ms stop');
      await wait(500);
      await streamProcessor.shutdown();
      console.timeEnd('500ms stop');
    };

    await streamTestStart();
    await streamTestStop();

    // Shudown action should stop stream handler right away
    const totalTime = Date.now() - startTime;
    expect(totalTime).toBeLessThan(2_000);
    expect(totalTime).toBeGreaterThan(200);
  });
});
