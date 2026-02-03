export const pushAll = <T>(target: T[], source: Iterable<T>): number => {
  for (const item of source) {
    target.push(item);
  }
  return target.length;
};
