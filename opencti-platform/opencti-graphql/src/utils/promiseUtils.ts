/**
 * Execute async operations with concurrency control.
 * Modern native alternative to Bluebird's Promise.map with concurrency.
 *
 * @param items - Array of items to process
 * @param mapper - Async function to apply to each item
 * @param concurrency - Maximum number of concurrent operations
 * @returns Promise resolving to array of results
 *
 * @example
 * const results = await promiseMap(
 *   files,
 *   (file) => processFile(file),
 *   5 // process 5 files at a time
 * );
 */
export const promiseMap = async <T, R>(
  items: T[],
  mapper: (item: T, index: number) => Promise<R>,
  concurrency: number
): Promise<R[]> => {
  const results: R[] = [];

  for (let i = 0; i < items.length; i += concurrency) {
    const chunk = items.slice(i, i + concurrency);
    const chunkResults = await Promise.all(
      chunk.map((item, chunkIndex) => mapper(item, i + chunkIndex))
    );
    results.push(...chunkResults);
  }

  return results;
};
