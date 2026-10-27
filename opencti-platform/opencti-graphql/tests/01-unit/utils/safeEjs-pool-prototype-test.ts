import { afterAll, describe, expect, it } from 'vitest';

// A dedicated file so the pool loads fresh and spawns its first worker while the prototype is set
// (ci-unit isolates modules per file).
describe('check safeRenderClient worker options', () => {
  const prototype = Object.prototype as Record<string, unknown>;

  afterAll(async () => {
    delete prototype.execArgv;
    const { shutdownSafeEjsPool } = await import('../../../src/utils/safeEjs.pool');
    await shutdownSafeEjsPool();
  });

  it('spawns its workers without reading execArgv from the object prototype', async () => {
    // Node rejects this flag for a worker: a worker started with it would fail to spawn
    prototype.execArgv = ['--title=inherited-exec-argv'];
    const { safeRender } = await import('../../../src/utils/safeEjs.client');
    expect(await safeRender('<%= it.value %>', { it: { value: 'rendered' } })).toBe('rendered');
  });
});
