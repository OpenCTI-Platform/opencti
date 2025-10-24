import { describe, expect, it } from 'vitest';
import { asyncFilter, largeArrayPush, largeArrayUnshift } from '../../../src/utils/data-processing';

describe('Data processing tests', () => {
  it('Filter processing data', async () => {
    const elements = ['Report', 'City', 'Region', 'Malware'];
    const predicate = (item: string) => item === 'Report';
    const asyncTypes = await asyncFilter(elements, predicate);
    expect(asyncTypes.length).toEqual(1);
    expect(asyncTypes[0]).toEqual('Report');
    const syncTypes = elements.filter(predicate);
    expect(syncTypes.length).toEqual(1);
    expect(syncTypes[0]).toEqual('Report');
  });

  it('Large array push', () => {
    const largeArrayPushResult = ['a', 'b', 'c'];
    const pushResult = [...largeArrayPushResult];
    const toBePushed = ['d', 'e', 'f'];

    largeArrayPush(largeArrayPushResult, toBePushed);
    pushResult.push(...toBePushed);

    expect(largeArrayPushResult).toStrictEqual(pushResult);
  });

  it('Large array unshift', () => {
    const largeArrayUnshiftResult = ['a', 'b', 'c'];
    const unshiftResult = [...largeArrayUnshiftResult];
    const toBeUnshift = ['d', 'e', 'f'];

    largeArrayUnshift(largeArrayUnshiftResult, toBeUnshift);
    unshiftResult.unshift(...toBeUnshift);

    expect(largeArrayUnshiftResult).toStrictEqual(unshiftResult);
  });
});
