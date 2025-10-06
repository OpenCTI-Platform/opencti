import { MAX_EVENT_LOOP_PROCESSING_TIME } from '../database/utils';

// Filter an array without blocking the event loop
// Instead of using ARRAY.filter(predicate) use asyncFilter(ARRAY, predicate)
export const asyncFilter = async <T>(elements: T[], predicate: (value: T, index: number) => boolean) => {
  const filtered: T[] = [];
  let startProcessingTime = new Date().getTime();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    if (predicate(element, index)) {
      filtered.push(element);
    }
    // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
  return filtered;
};

export const asyncMap = async <T, Z>(elements: T[], transform: (value: T) => Z | Promise<Z>, filter?: (value: Z) => boolean, opts: { flat?: boolean } = {}) => {
  const { flat = false } = opts;
  const transformed: Z[] = [];
  let startProcessingTime = new Date().getTime();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    let item = transform(element); // can be one element or array
    if (item instanceof Promise) {
      item = await item;
    }
    if (!filter || filter(item)) {
      if (flat && Array.isArray(item)) {
        for (let j = 0; j < item.length; j += 1) {
          transformed.push(item[j]);
          // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
          if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
            startProcessingTime = new Date().getTime();
            await new Promise((resolve) => {
              setImmediate(resolve);
            });
          }
        }
      } else {
        transformed.push(item);
      }
    }
    // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
  return transformed;
};

export const uniqAsyncMap = async <T, Z>(elements: T[], transform: (value: T) => Z, filter?: (value: Z) => boolean, opts: { flat?: boolean } = {}) => {
  const { flat = false } = opts;
  const transformedSet: Set<Z> = new Set();
  let startProcessingTime = new Date().getTime();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const item = transform(element); // can be one element or array
    if (!filter || filter(item)) {
      if (flat && Array.isArray(item)) {
        for (let j = 0; j < item.length; j += 1) {
          transformedSet.add(item[j]);
          // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
          if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
            startProcessingTime = new Date().getTime();
            await new Promise((resolve) => {
              setImmediate(resolve);
            });
          }
        }
      } else {
        transformedSet.add(item);
      }
    }
    // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
  return Array.from(transformedSet);
};
