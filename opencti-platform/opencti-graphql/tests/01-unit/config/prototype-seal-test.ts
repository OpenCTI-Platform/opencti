import { describe, expect, it } from 'vitest';
import { Worker } from 'worker_threads';
import '../../../src/config/prototype-seal';

// A dedicated file: the seal applies to the whole test process (ci-unit isolates each test file).
describe('Object.prototype seal', () => {
  it('should forbid adding a property to Object.prototype', () => {
    expect(Object.isSealed(Object.prototype)).toBe(true);
    expect(() => {
      (Object.prototype as Record<string, unknown>).added = true;
    }).toThrow(TypeError);
    expect(({} as Record<string, unknown>).added).toBeUndefined();
  });

  it('should keep the existing members writable on inheriting prototypes', () => {
    function Legacy() {}
    Legacy.prototype.toString = () => 'legacy';
    Legacy.prototype.valueOf = () => 42;
    const literalPrototype: Record<string, unknown> = {};
    literalPrototype.constructor = Legacy;
    expect(String(Reflect.construct(Legacy, []))).toBe('legacy');
    expect(Number(Reflect.construct(Legacy, []))).toBe(42);
    expect(literalPrototype.constructor).toBe(Legacy);
  });

  it('should seal Object.prototype in the safeEjs worker, which has its own', async () => {
    const workerUrl = new URL('../../../build/safeEjs.worker.mjs', import.meta.url).href;
    const probe = new Worker(`
      const { parentPort } = require('worker_threads');
      import(${JSON.stringify(workerUrl)}).then(() => parentPort.postMessage(Object.isSealed(Object.prototype)));
    `, { eval: true });
    try {
      const sealed = await new Promise((resolve, reject) => {
        probe.once('message', resolve);
        probe.once('error', reject);
      });
      expect(sealed).toBe(true);
    } finally {
      await probe.terminate();
    }
  });
});
