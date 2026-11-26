import useVisibleEntries from './useVisibleEntries';
import type { MenuEntry } from './menuEntry';

/**
 * Where to send a user landing on a section (or denied a page): the first of `entries` they can open, by the same rules
 * as the left bar, or `fallback` when there is none. Pass the entries in left bar order (`sectionEntries`).
 */
const useFirstVisiblePath = (entries: MenuEntry[], fallback = '/dashboard'): string => useVisibleEntries(entries)[0]?.path ?? fallback;

export default useFirstVisiblePath;
