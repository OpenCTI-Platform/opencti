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

export const memoizeAsync = <A extends unknown[], R>(
  fun: (...args: A) => Promise<R>,
  keyOf: (...args: A) => string = () => '',
) => {
  const cache = new Map<string, Promise<R>>();
  const run = async (key: string, args: A): Promise<R> => {
    try {
      return await fun(...args);
    } catch (error) {
      cache.delete(key);
      throw error;
    }
  };
  return (...args: A): Promise<R> => {
    const key = keyOf(...args);
    let result = cache.get(key);
    if (!result) {
      result = run(key, args);
      cache.set(key, result);
    }
    return result;
  };
};
