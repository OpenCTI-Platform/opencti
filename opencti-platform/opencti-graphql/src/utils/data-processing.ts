import { doYield } from './eventloop-utils';

// Filter an array without blocking the event loop
// Instead of using ARRAY.filter(predicate) use asyncFilter(ARRAY, predicate)
export const asyncFilter = async <T>(elements: T[], predicate: (value: T, index: number) => boolean) => {
  const filtered: T[] = [];
  for (let index = 0; index < elements.length; index += 1) {
    await doYield();
    const element = elements[index];
    if (predicate(element, index)) {
      filtered.push(element);
    }
  }
  return filtered;
};

export const asyncMap = async <T, Z>(elements: T[], transform: (value: T) => Z | Promise<Z>, filter?: (value: Z) => boolean, opts: { flat?: boolean } = {}) => {
  const { flat = false } = opts;
  const transformed: Z[] = [];
  for (let index = 0; index < elements.length; index += 1) {
    await doYield();
    const element = elements[index];
    let item = transform(element); // can be one element or array
    if (item instanceof Promise) {
      item = await item;
    }
    if (!filter || filter(item)) {
      if (flat && Array.isArray(item)) {
        for (let j = 0; j < item.length; j += 1) {
          await doYield();
          transformed.push(item[j]);
        }
      } else {
        transformed.push(item);
      }
    }
  }
  return transformed;
};

export const uniqAsyncMap = async <T, Z>(elements: T[], transform: (value: T) => Z, filter?: (value: Z) => boolean, opts: { flat?: boolean } = {}) => {
  const { flat = false } = opts;
  const transformedSet: Set<Z> = new Set();
  for (let index = 0; index < elements.length; index += 1) {
    await doYield();
    const element = elements[index];
    const item = transform(element); // can be one element or array
    if (!filter || filter(item)) {
      if (flat && Array.isArray(item)) {
        for (let j = 0; j < item.length; j += 1) {
          await doYield();
          transformedSet.add(item[j]);
        }
      } else {
        transformedSet.add(item);
      }
    }
  }
  return Array.from(transformedSet);
};
