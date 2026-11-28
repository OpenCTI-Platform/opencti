import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';
import type { SavedView } from './builtinViews';
import type { CanvasSnapshot } from './canvasSnapshot';

interface SavedViewsState {
  views: SavedView[];
  addView: (name: string, snapshot: CanvasSnapshot) => string;
  renameView: (id: string, name: string) => void;
  updateView: (id: string, snapshot: CanvasSnapshot) => void;
  removeView: (id: string) => void;
}

const newId = () => `user:${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;

/** User-defined "subject areas", kept in the browser. Built-in views live in builtinViews.ts. */
export const useSavedViewsStore = create<SavedViewsState>()(persist(
  (set, get) => ({
    views: [],
    addView: (name, snapshot) => {
      const id = newId();
      set({ views: [...get().views, { id, name, icon: 'bookmark', builtin: false, snapshot }] });
      return id;
    },
    renameView: (id, name) => set({ views: get().views.map((view) => (view.id === id ? { ...view, name } : view)) }),
    updateView: (id, snapshot) => set({ views: get().views.map((view) => (view.id === id ? { ...view, snapshot } : view)) }),
    removeView: (id) => set({ views: get().views.filter((view) => view.id !== id) }),
  }),
  {
    name: 'opencti-schema-viz:saved-views',
    version: 1,
    storage: createJSONStorage(() => localStorage),
  },
));
