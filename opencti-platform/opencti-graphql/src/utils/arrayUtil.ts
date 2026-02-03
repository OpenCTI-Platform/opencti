export const pushAll = <T>(target: T[], source: Iterable<T>): number => {
  // Guard against infinite loop when source === target by iterating over a shallow copy
  const itemsToAdd = source === target ? [...source] : source;
  for (const item of itemsToAdd) {
    target.push(item);
  }
  return target.length;
};
