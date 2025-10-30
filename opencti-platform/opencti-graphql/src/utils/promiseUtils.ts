export class TimeoutError extends Error {
  name = 'TimeoutError';
}

export const callWithTimeout = async <T>(promise: Promise<T>, timeout: number): Promise<T> => {
  let timeoutHandle: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutHandle = setTimeout(() => reject(new TimeoutError('Operation timed out.')), timeout);
  });
  try {
    const result = await Promise.race([promise, timeoutPromise]);
    return result as T; // only 'promise' can resolve
  } finally {
    clearTimeout(timeoutHandle!);
  }
};
