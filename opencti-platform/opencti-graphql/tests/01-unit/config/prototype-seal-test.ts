import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import '../../../src/config/prototype-seal';

const PACKAGE_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SEAL_MODULE = path.join(PACKAGE_ROOT, 'src/config/prototype-seal.ts');

// The list belongs to the tool project (tsconfig.tool.json), which the test project does not reference:
// a dynamic import keeps the type checker out of it.
const ENTRY_POINTS_MODULE = new URL('../../../builder/entry-points.ts', import.meta.url).href;
const { BUILD_ENTRY_POINTS } = await import(ENTRY_POINTS_MODULE) as { BUILD_ENTRY_POINTS: string[] };

// One-off scripts an operator runs by hand: they never process user input.
const UNSEALED_ENTRY_POINTS = ['script/script-clean-relations.ts', 'script/script-insert-dataset.ts'];
const SEALED_ENTRY_POINTS = BUILD_ENTRY_POINTS.filter((entryPoint) => !UNSEALED_ENTRY_POINTS.includes(entryPoint));

// Resolves the module the file's first statement imports, when that statement is a side-effect import.
const resolveFirstSideEffectImport = (entryPoint: string) => {
  const filePath = path.join(PACKAGE_ROOT, entryPoint);
  const source = ts.createSourceFile(filePath, fs.readFileSync(filePath, 'utf8'), ts.ScriptTarget.Latest);
  const [first] = source.statements;
  if (!first || !ts.isImportDeclaration(first) || first.importClause || !ts.isStringLiteral(first.moduleSpecifier)) {
    return undefined;
  }
  return path.resolve(path.dirname(filePath), `${first.moduleSpecifier.text}.ts`);
};

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

  // Each process or thread has its own Object.prototype, and the seal only works if it lands before
  // any dependency loads. Checked on the sources, so it holds without a build and fails on a new entry
  // point or on an import sort that moves the seal down.
  it.each(SEALED_ENTRY_POINTS)('should seal Object.prototype first in the %s entry point', (entryPoint) => {
    expect(resolveFirstSideEffectImport(entryPoint), `${entryPoint} must start with: import '<relative path>/config/prototype-seal';`)
      .toBe(SEAL_MODULE);
  });
});
