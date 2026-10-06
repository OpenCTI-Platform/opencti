/** The entries a hub registry collects from its files (`import.meta.glob`), in their declared order. */
export const sortedHubEntries = <T extends { order: number }>(modules: Record<string, T>): T[] => (
  Object.values(modules).sort((a, b) => a.order - b.order)
);

/**
 * A hub is listed in the menu while one of its registered entries is visible to the reader, and while
 * no entry is registered at all, its landing page then saying that its pages are not available yet.
 * A hub whose registered entries are all hidden from the reader is not listed.
 */
export const isHubListed = (registered: readonly unknown[], visible: readonly unknown[]): boolean => (
  registered.length === 0 || visible.length > 0
);
