import { create } from 'zustand';
import { loadSchema as loadNormalizedSchema, type SchemaSource } from '../data/schemaLoader';
import type { NormalizedSchema, SchemaPath, ToggleableCategory } from '../data/schemaTypes';
import { DEFAULT_FIND_PATH_OPTIONS, type FindPathOptions } from '../features/find-path/findShortestPath';
import { parseRevealKey } from '../features/schema-graph/graphIds';
import type { LayoutDirection } from '../features/schema-graph/layout/LayoutEngine';
import { TOGGLEABLE_CATEGORIES } from '../shared/theme/typeAppearance';
import { type CanvasSnapshot, EMPTY_SNAPSHOT } from './canvasSnapshot';

const HISTORY_LIMIT = 12;

export interface CameraRequest {
  nonce: number;
  /** null fits the whole canvas. */
  typeIds: string[] | null;
  /** Also frame what is connected to typeIds. */
  withNeighbors: boolean;
}

export interface FindPathState {
  open: boolean;
  fromTypeId: string | null;
  toTypeId: string | null;
  options: FindPathOptions;
}

interface SchemaGraphState extends CanvasSnapshot {
  status: 'idle' | 'loading' | 'ready' | 'error';
  error: string | null;
  schema: NormalizedSchema | null;

  selectedTypeId: string | null;
  /** Breadcrumb: types visited, oldest first. */
  history: string[];
  path: SchemaPath | null;
  findPath: FindPathState;
  activeViewId: string | null;
  camera: CameraRequest;
  paletteOpen: boolean;

  loadSchema: (source?: SchemaSource) => Promise<void>;
  applySnapshot: (snapshot: CanvasSnapshot, viewId: string | null) => void;
  snapshot: () => CanvasSnapshot;

  selectType: (typeId: string | null) => void;
  focusType: (typeId: string) => void;
  navigateToCrumb: (index: number) => void;
  togglePinned: (typeId: string) => void;
  pinTypes: (typeIds: string[]) => void;
  /** Also forgets what was expanded or revealed from these types. */
  unpinTypes: (typeIds: string[]) => void;
  toggleExpand: (typeId: string) => void;
  toggleReveal: (key: string, anchorTypeId: string) => void;
  clearCanvas: () => void;

  setCategoryEnabled: (category: ToggleableCategory, enabled: boolean) => void;
  setAllCategories: (enabled: boolean) => void;
  setShowInheritance: (value: boolean) => void;
  setShowRelations: (value: boolean) => void;
  setIncludeRefs: (value: boolean) => void;
  setDirection: (direction: LayoutDirection) => void;

  openFindPath: (fromTypeId?: string | null) => void;
  closeFindPath: () => void;
  setFindPath: (patch: Partial<Omit<FindPathState, 'open'>>) => void;
  showPath: (path: SchemaPath) => void;
  clearPath: () => void;

  requestCamera: (typeIds: string[] | null, withNeighbors?: boolean) => void;
  setPaletteOpen: (open: boolean) => void;
}

const withToggled = (values: readonly string[], value: string) => (values.includes(value)
  ? values.filter((existing) => existing !== value)
  : [...values, value]);

export const useSchemaGraphStore = create<SchemaGraphState>()((set, get) => {
  const camera = (typeIds: string[] | null, withNeighbors = false): Pick<SchemaGraphState, 'camera'> => ({
    camera: { nonce: get().camera.nonce + 1, typeIds, withNeighbors },
  });

  /** Makes sure types can be seen: pinned, and their categories switched on. One patch for any number of types. */
  const revealAll = (typeIds: readonly string[]): Partial<SchemaGraphState> => {
    const { schema, pinnedTypeIds, enabledCategories } = get();
    const pinned = new Set(pinnedTypeIds);
    const categories = { ...enabledCategories };
    for (const typeId of typeIds) {
      pinned.add(typeId);
      const category = schema?.types.get(typeId)?.category;
      if (category && category !== 'Abstract') categories[category] = true;
    }
    return { pinnedTypeIds: [...pinned], enabledCategories: categories };
  };
  const reveal = (typeId: string) => revealAll([typeId]);

  const visit = (typeId: string): Pick<SchemaGraphState, 'selectedTypeId' | 'history'> => {
    const { history } = get();
    const index = history.indexOf(typeId);
    const next = index >= 0 ? history.slice(0, index + 1) : [...history, typeId].slice(-HISTORY_LIMIT);
    return { selectedTypeId: typeId, history: next };
  };

  return {
    ...EMPTY_SNAPSHOT,
    status: 'idle',
    error: null,
    schema: null,
    selectedTypeId: null,
    history: [],
    path: null,
    findPath: { open: false, fromTypeId: null, toTypeId: null, options: DEFAULT_FIND_PATH_OPTIONS },
    activeViewId: null,
    camera: { nonce: 0, typeIds: null, withNeighbors: false },
    paletteOpen: false,

    loadSchema: async (source) => {
      set({ status: 'loading', error: null });
      try {
        const schema = await loadNormalizedSchema(source);
        set({ schema, status: 'ready' });
      } catch (error) {
        set({ status: 'error', error: error instanceof Error ? error.message : String(error) });
      }
    },

    applySnapshot: (snapshot, viewId) => set({
      ...snapshot,
      activeViewId: viewId,
      path: null,
      ...camera(null),
    }),

    snapshot: () => {
      const { pinnedTypeIds, expandedTypeIds, revealedRelations, enabledCategories, showInheritance, showRelations, includeRefs, direction } = get();
      return { pinnedTypeIds, expandedTypeIds, revealedRelations, enabledCategories, showInheritance, showRelations, includeRefs, direction };
    },

    selectType: (typeId) => {
      if (typeId === null) {
        set({ selectedTypeId: null });
        return;
      }
      set({ ...reveal(typeId), ...visit(typeId) });
    },

    focusType: (typeId) => set({ ...reveal(typeId), ...visit(typeId), path: null, ...camera([typeId]) }),

    navigateToCrumb: (index) => {
      const { history } = get();
      if (index < 0) {
        set({ selectedTypeId: null, history: [], ...camera(null) });
        return;
      }
      const typeId = history[index];
      if (typeId) set({ ...reveal(typeId), selectedTypeId: typeId, history: history.slice(0, index + 1), ...camera([typeId]) });
    },

    togglePinned: (typeId) => {
      if (get().pinnedTypeIds.includes(typeId)) get().unpinTypes([typeId]);
      else set(reveal(typeId));
    },

    pinTypes: (typeIds) => set(revealAll(typeIds)),

    unpinTypes: (typeIds) => {
      const removed = new Set(typeIds);
      const { pinnedTypeIds, expandedTypeIds, revealedRelations, selectedTypeId } = get();
      set({
        pinnedTypeIds: pinnedTypeIds.filter((id) => !removed.has(id)),
        expandedTypeIds: expandedTypeIds.filter((id) => !removed.has(id)),
        revealedRelations: revealedRelations.filter((key) => !removed.has(parseRevealKey(key).anchorTypeId)),
        selectedTypeId: selectedTypeId && removed.has(selectedTypeId) ? null : selectedTypeId,
      });
    },

    toggleExpand: (typeId) => {
      const expanding = !get().expandedTypeIds.includes(typeId);
      set({
        ...reveal(typeId),
        expandedTypeIds: withToggled(get().expandedTypeIds, typeId),
        path: null,
        // Selecting the expanded type puts its relations in focus and dims the rest.
        ...(expanding ? { ...visit(typeId), ...camera([typeId], true) } : {}),
      });
    },

    toggleReveal: (key, anchorTypeId) => set({
      ...reveal(anchorTypeId),
      revealedRelations: withToggled(get().revealedRelations, key),
      path: null,
    }),

    clearCanvas: () => set({ pinnedTypeIds: [], expandedTypeIds: [], revealedRelations: [], selectedTypeId: null, path: null, activeViewId: null }),

    setCategoryEnabled: (category, enabled) => set({ enabledCategories: { ...get().enabledCategories, [category]: enabled } }),
    setAllCategories: (enabled) => set({
      enabledCategories: Object.fromEntries(TOGGLEABLE_CATEGORIES.map((category) => [category, enabled])) as Record<ToggleableCategory, boolean>,
    }),
    setShowInheritance: (showInheritance) => set({ showInheritance }),
    setShowRelations: (showRelations) => set({ showRelations }),
    setIncludeRefs: (includeRefs) => set({ includeRefs }),
    setDirection: (direction) => set({ direction, ...camera(null) }),

    openFindPath: (fromTypeId) => set({
      findPath: { ...get().findPath, open: true, ...(fromTypeId !== undefined ? { fromTypeId } : {}) },
    }),
    closeFindPath: () => set({ findPath: { ...get().findPath, open: false } }),
    setFindPath: (patch) => set({ findPath: { ...get().findPath, ...patch } }),
    showPath: (path) => set({ path, selectedTypeId: null, ...camera(null) }),
    clearPath: () => set({ path: null, ...camera(null) }),

    requestCamera: (typeIds, withNeighbors = false) => set(camera(typeIds, withNeighbors)),
    setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
  };
});
