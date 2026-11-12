/**
 * The entities hidden in a graph, saved for that graph in local storage only, never in the URL
 * with the rest of its view state: the list grows with every entity hidden (thousands on a large
 * graph), far beyond the length a URL can carry.
 */
const hiddenNodesKey = (viewKey: string) => `${viewKey}-hidden-nodes`;

export const readHiddenNodeIds = (viewKey: string): string[] => {
  try {
    const stored: unknown = JSON.parse(window.localStorage.getItem(hiddenNodesKey(viewKey)) ?? '[]');
    return Array.isArray(stored) ? stored.map(String) : [];
  } catch {
    return [];
  }
};

export const writeHiddenNodeIds = (viewKey: string, ids: readonly string[]) => {
  try {
    if (ids.length === 0) window.localStorage.removeItem(hiddenNodesKey(viewKey));
    else window.localStorage.setItem(hiddenNodesKey(viewKey), JSON.stringify(ids));
  } catch {
    // Storage refused (private mode, quota): the entities stay hidden until the page is left.
  }
};
