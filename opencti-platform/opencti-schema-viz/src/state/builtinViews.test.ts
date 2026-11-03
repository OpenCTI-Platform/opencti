import { describe, expect, it } from 'vitest';
import { buildVisibleGraph } from '../features/schema-graph/buildVisibleGraph';
import { loadRealSchema } from '../test/fixtures';
import { BUILTIN_VIEWS, resolveBuiltinViews } from './builtinViews';

const schema = loadRealSchema();

describe('built-in views on the generated schema.json', () => {
  it.each(BUILTIN_VIEWS.map((view) => [view.name, view.id]))('%s only references existing types', (_name, id) => {
    const view = BUILTIN_VIEWS.find((candidate) => candidate.id === id);
    // A schema that claims to know every id shows what the view declares, before missing ids are dropped.
    const permissiveTypes = Object.assign(new Map(schema.types), { has: () => true });
    const declared = view?.resolve({ ...schema, types: permissiveTypes });
    const resolved = resolveBuiltinViews(schema).find((candidate) => candidate.id === id);
    expect(resolved?.snapshot.pinnedTypeIds.length).toBeGreaterThan(0);
    expect(resolved?.snapshot.pinnedTypeIds).toEqual(declared?.pinnedTypeIds);
  });

  it('keeps the default view readable', () => {
    const [defaultView] = resolveBuiltinViews(schema);
    const graph = buildVisibleGraph(schema, { ...defaultView.snapshot, path: null });
    expect(defaultView.snapshot.pinnedTypeIds).toHaveLength(7);
    expect(graph.edges.length).toBeLessThanOrEqual(25);
  });
});
