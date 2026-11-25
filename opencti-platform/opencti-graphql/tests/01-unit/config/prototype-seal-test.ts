import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import esbuild from 'esbuild';
import '../../../src/config/prototype-seal';
import { BUILD_INJECTED_MODULES } from '../../../builder/injected-modules';

const PACKAGE_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

const SEALED_CONSTRUCTORS = [
  'Object', 'Array', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Function',
  'RegExp', 'Date', 'Error', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet',
];
const prototypeOf = (scope: object, name: string) => (Reflect.get(scope, name) as { prototype: object }).prototype;

// A dedicated file: the seal applies to the whole test process (ci-unit isolates each test file).
describe('Built-in prototypes seal', () => {
  it.each(SEALED_CONSTRUCTORS)('should seal %s.prototype without freezing it', (name) => {
    const prototype = prototypeOf(globalThis, name);
    expect(Object.isSealed(prototype)).toBe(true);
    expect(Object.isFrozen(prototype)).toBe(false);
  });

  it('should forbid adding a property to Object.prototype or Array.prototype', () => {
    expect(() => {
      (Object.prototype as Record<string, unknown>).added = true;
    }).toThrow(TypeError);
    expect(({} as Record<string, unknown>).added).toBeUndefined();
    // What a naive recursive merge of {"tags": {"__proto__": {"added": true}}} into { tags: [] } would do.
    expect(() => {
      Object.assign(Object.getPrototypeOf([]), { added: true });
    }).toThrow(TypeError);
    expect(([] as unknown as Record<string, unknown>).added).toBeUndefined();
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

  // Each process or thread has its own built-in prototypes, and the seal only works if it lands before any
  // dependency loads. Bundles a stand-in entry point with the build's injected modules and runs it in a
  // fresh context, whose prototypes this test process has not sealed. No full build needed.
  it('should seal the built-in prototypes before the code of every built entry point', async () => {
    const names = JSON.stringify(SEALED_CONSTRUCTORS);
    const { outputFiles } = await esbuild.build({
      stdin: { contents: `globalThis.unsealedOnEntry = ${names}.filter((name) => !Object.isSealed(globalThis[name].prototype));`, resolveDir: PACKAGE_ROOT },
      inject: BUILD_INJECTED_MODULES,
      absWorkingDir: PACKAGE_ROOT,
      bundle: true,
      platform: 'node',
      write: false,
      logLevel: 'silent',
    });
    const context = vm.createContext({});
    vm.runInContext(outputFiles[0].text, context);
    expect(Array.from(context.unsealedOnEntry)).toEqual([]);
  });
});
