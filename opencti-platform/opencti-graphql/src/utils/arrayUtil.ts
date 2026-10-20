/**
 * Coerces a value to an array: an array is returned as is, any other value is wrapped.
 * `null` and `undefined` give an empty array. With `falsyAsEmpty`, so do `''`, `0` and `false`
 * (e.g. xml2js parses an empty tag as `''`).
 */
export const asArray = (value: unknown, { falsyAsEmpty = false }: { falsyAsEmpty?: boolean } = {}): any[] => {
  if (value === undefined || value === null || (falsyAsEmpty && !value)) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

export const pushAll = <T>(target: T[], source: Iterable<T>): number => {
  // Guard against infinite loop when source === target by iterating over a shallow copy
  const itemsToAdd = source === target ? [...source] : source;
  for (const item of itemsToAdd) {
    target.push(item);
  }
  return target.length;
};

export const unshiftAll = <T>(target: T[], source: T[]): number => {
  const m = source.length;
  if (m !== 0) {
    const n = target.length;
    target.length = n + m;

    // Shift existing elements right by m
    for (let i = n - 1; i >= 0; i--) {
      target[i + m] = target[i];
    }

    // Copy new items at the front
    for (let i = 0; i < m; i++) {
      target[i] = source[i];
    }
  }

  return target.length;
};
