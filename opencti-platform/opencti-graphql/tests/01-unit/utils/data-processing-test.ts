import { describe, expect, it } from 'vitest';
import { asyncFilter } from '../../../src/utils/data-processing';

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
});
