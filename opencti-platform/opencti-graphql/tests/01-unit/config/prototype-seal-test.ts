import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import esbuild from 'esbuild';
import '../../../src/config/prototype-seal';

const PACKAGE_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

// The list belongs to the tool project (tsconfig.tool.json), which the test project does not reference:
// a dynamic import keeps the type checker out of it.
const ENTRY_POINTS_MODULE = new URL('../../../builder/entry-points.ts', import.meta.url).href;
const { BUILD_INJECTED_MODULES } = await import(ENTRY_POINTS_MODULE) as { BUILD_INJECTED_MODULES: string[] };

// A dedicated file: the seal applies to the whole test process (ci-unit isolates each test file).
describe('Object.prototype seal', () => {
  it('should forbid adding a property to Object.prototype', () => {
    expect(Object.isSealed(Object.prototype)).toBe(true);
    expect(() => {
      (Object.prototype as Record<string, unknown>).added = true;
    }).toThrow(TypeError);
    expect(({} as Record<string, unknown>).added).toBeUndefined();
  });

  it('should keep Object.prototype members writable, as dependencies override them on their own prototypes', () => {
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'toString')?.writable).toBe(true);
    // Each assignment below throws in strict mode once Object.prototype is frozen instead of sealed:
    // an inherited member that is not writable cannot be shadowed by a plain assignment.
    function Legacy() {}
    Legacy.prototype.toString = () => 'legacy';
    Legacy.prototype.valueOf = () => 42;
    const literalPrototype: Record<string, unknown> = {};
    literalPrototype.constructor = Legacy;
    expect(String(Reflect.construct(Legacy, []))).toBe('legacy');
    expect(Number(Reflect.construct(Legacy, []))).toBe(42);
    expect(literalPrototype.constructor).toBe(Legacy);
  });

  // Each process or thread has its own Object.prototype, and the seal only works if it lands before any
  // dependency loads. Bundles a stand-in entry point with the build's injected modules and runs it in a
  // fresh context, whose Object.prototype this test process has not sealed. No full build needed.
  it('should seal Object.prototype before the code of every built entry point', async () => {
    const { outputFiles } = await esbuild.build({
      stdin: { contents: 'globalThis.sealedOnEntry = Object.isSealed(Object.prototype);', resolveDir: PACKAGE_ROOT },
      inject: BUILD_INJECTED_MODULES,
      absWorkingDir: PACKAGE_ROOT,
      bundle: true,
      platform: 'node',
      write: false,
      logLevel: 'silent',
    });
    const context = vm.createContext({});
    vm.runInContext(outputFiles[0].text, context);
    expect(context.sealedOnEntry).toBe(true);
  });
});
