export const memoize = <T>(fun: () => T) => {
  let memoized: T;
  let computed = false;
  return (): T => {
    if (!computed) {
      memoized = fun();
      computed = true;
    }
    return memoized;
  };
};
