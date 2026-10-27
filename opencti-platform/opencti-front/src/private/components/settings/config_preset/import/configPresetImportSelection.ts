import type { ConfigPresetSelection } from '../configPresetSelection';

// The selection as the session stores it, by type
export interface ConfigPresetSessionSelection {
  readonly type: string;
  readonly items?: ReadonlyArray<string> | null;
  readonly excluded_items?: ReadonlyArray<string> | null;
}

// The saved selection of the session as the selection of the list: every item but the excluded ones ('all'), or only the listed ones
export const toConfigPresetSelection = (selections: ReadonlyArray<ConfigPresetSessionSelection>): ConfigPresetSelection => {
  return Object.fromEntries(selections.map(({ type, items, excluded_items }) => [
    type,
    items ? { mode: 'some', ids: [...items] } : { mode: 'all', ids: [...(excluded_items ?? [])] },
  ]));
};
