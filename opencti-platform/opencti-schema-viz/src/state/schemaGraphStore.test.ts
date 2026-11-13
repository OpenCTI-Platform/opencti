import { beforeEach, describe, expect, it } from 'vitest';
import { revealKey } from '../features/schema-graph/graphIds';
import { buildFixtureSchema } from '../test/fixtures';
import { EMPTY_SNAPSHOT } from './canvasSnapshot';
import { useSchemaGraphStore } from './schemaGraphStore';

const store = useSchemaGraphStore;

describe('schemaGraphStore pinning', () => {
  beforeEach(() => {
    store.setState({ ...EMPTY_SNAPSHOT, schema: buildFixtureSchema(), selectedTypeId: null });
  });

  it('pins many types in one update and switches their categories on', () => {
    // In the fixture, relationship types have no stix-relationship root, so they are Internal (hidden by default).
    expect(store.getState().enabledCategories.Internal).toBe(false);
    let updates = 0;
    const unsubscribe = store.subscribe(() => { updates += 1; });
    store.getState().pinTypes(['Malware', 'Tool', 'uses']);
    unsubscribe();
    expect(updates).toBe(1);
    expect(store.getState().pinnedTypeIds).toEqual(['Malware', 'Tool', 'uses']);
    expect(store.getState().enabledCategories.Internal).toBe(true);
  });

  it('forgets what was expanded or revealed from an unpinned type', () => {
    const kept = revealKey('out', 'Tool', 'Tool_related-to');
    store.setState({
      pinnedTypeIds: ['Malware', 'Tool'],
      expandedTypeIds: ['Malware'],
      revealedRelations: [revealKey('out', 'Malware', 'Malware_uses'), kept],
      selectedTypeId: 'Malware',
    });
    store.getState().togglePinned('Malware');
    const state = store.getState();
    expect(state.pinnedTypeIds).toEqual(['Tool']);
    expect(state.expandedTypeIds).toEqual([]);
    expect(state.revealedRelations).toEqual([kept]);
    expect(state.selectedTypeId).toBeNull();
  });
});
