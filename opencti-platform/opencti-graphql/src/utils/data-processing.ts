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

export const asyncMap = async <T, Z>(elements: T[], transform: (value: T) => Z, filter?: (value: Z) => boolean, opts: { flat?: boolean } = {}) => {
  const { flat = false } = opts;
  const transformed: Z[] = [];
  for (let index = 0; index < elements.length; index += 1) {
    await doYield();
    const element = elements[index];
    const item = transform(element); // can be one element or array
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

export function largeArrayPush<T>(dst: T[], src: T[]): void {
  const start = dst.length;
  // grow array once
  // eslint-disable-next-line no-param-reassign
  dst.length += src.length;
  for (let i = 0; i < src.length; i += 1) {
    // eslint-disable-next-line no-param-reassign
    dst[start + i] = src[i];
  }
}

export const largeArrayUnshift = <T>(dst: T[], src: T[]) => {
  const m = src.length;
  const n = dst.length;

  // Grow once
  // eslint-disable-next-line no-param-reassign
  dst.length = n + m;

  // Shift right existing elements (right-to-left to avoid overwrite)
  for (let i = n - 1; i >= 0; i -= 1) {
    // eslint-disable-next-line no-param-reassign
    dst[i + m] = dst[i];
  }

  // Copy src into the newly freed prefix
  for (let j = 0; j < m; j += 1) {
    // eslint-disable-next-line no-param-reassign
    dst[j] = src[j];
  }
};
