/** The entries a hub registry collects from its files (`import.meta.glob`), in their declared order. */
export const sortedHubEntries = <T extends { order: number }>(modules: Record<string, T>): T[] => (
  Object.values(modules).sort((a, b) => a.order - b.order)
);
