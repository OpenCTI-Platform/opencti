import { describe, it, expect, vi, afterAll } from 'vitest';
import { Worker } from 'worker_threads';
import conf from '../../../src/config/conf';

// A dedicated file so the pool loads fresh with a small retirement limit set before its first import
// (ci-unit isolates modules per file). This exercises the two behaviours the pool exists for: a worker
// is reused across renders, and it is retired (terminated) once it reaches max_renders_per_worker.
describe('check safeRenderClient worker lifecycle', () => {
  const originalMaxRenders = conf.get('safe_ejs:max_renders_per_worker');

  afterAll(() => {
    conf.set('safe_ejs:max_renders_per_worker', originalMaxRenders);
  });

  it('reuses one worker across renders and retires it at max_renders_per_worker', async () => {
    conf.set('safe_ejs:max_renders_per_worker', 2);
    const terminateSpy = vi.spyOn(Worker.prototype, 'terminate');
    const { safeRender } = await import('../../../src/utils/safeEjs.client');
    const { shutdownSafeEjsPool } = await import('../../../src/utils/safeEjs.pool');
    try {
      const rendered: string[] = [];
      for (let i = 0; i < 3; i += 1) {
        rendered.push(await safeRender('<%= it.i %>', { it: { i } }));
      }
      expect(rendered).toEqual(['0', '1', '2']);
      // Exactly one termination before shutdown: the first worker handled renders 0 and 1 (reuse:
      // acquire pops an idle worker before spawning), then crossed the limit of 2 and was terminated;
      // render 2 ran on a fresh, still-idle worker. A worker per render would terminate three times
      // (or none), and premature recycling would terminate more than once — this count catches both.
      expect(terminateSpy.mock.calls.length).toBe(1);
    } finally {
      terminateSpy.mockRestore();
      await shutdownSafeEjsPool();
    }
  });
});
