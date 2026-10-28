import type { ConfigPresetSelection } from '../configPresetSelection';
import { ConfigImportModes, isConfigImportMode } from '../configImportMode';

// The selection as the session stores it, by type
export interface ConfigPresetSessionSelection {
  readonly type: string;
  readonly items?: ReadonlyArray<string> | null;
  readonly excluded_items?: ReadonlyArray<string> | null;
  // Null for a selection saved before the modes existed
  readonly mode?: string | null;
}

// The saved selection of the session as the selection of the list: every item but the excluded ones ('all'), or only the listed ones
export const toConfigPresetSelection = (selections: ReadonlyArray<ConfigPresetSessionSelection>): ConfigPresetSelection => {
  return Object.fromEntries(selections.map(({ type, items, excluded_items }) => [
    type,
    items ? { mode: 'some', ids: [...items] } : { mode: 'all', ids: [...(excluded_items ?? [])] },
  ]));
};

// The modes of the session by type, the default one left out
export const toConfigImportModes = (selections: ReadonlyArray<ConfigPresetSessionSelection>): ConfigImportModes => {
  return Object.fromEntries(selections.flatMap(({ type, mode }) => (mode && mode !== 'OVERWRITE' && isConfigImportMode(mode) ? [[type, mode]] : [])));
};
