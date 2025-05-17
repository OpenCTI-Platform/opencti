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

export const asyncMap = async <T, Z>(elements: T[], transform: (value: T) => Z, filter?: (value: Z) => boolean) => {
  const transformed: Z[] = [];
  let startProcessingTime = new Date().getTime();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const item = transform(element);
    if (!filter || filter(item)) {
      transformed.push(item);
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
