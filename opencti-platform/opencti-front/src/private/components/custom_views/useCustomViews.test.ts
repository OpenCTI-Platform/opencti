import { afterEach, describe, it, expect, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import { useCustomViews } from './useCustomViews';
import { useCustomViewsData } from './useCustomViewsData';

vi.mock('./useCustomViewsData', () => ({
  useCustomViewsData: vi.fn().mockImplementation(() => ({
    allCustomViews: [],
    refetchCustomViews: () => ({ dispose: () => {} }),
  })),
}));

describe('useCustomViews', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });
  it('provides the list of custom views filtered by targetEntityType', () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: 'e8170a92-344d-4b17-815b-7eb2ec26430c',
        name: 'Basic view',
        path: 'basic-view-e8170a92344d4b17815b7eb2ec26430c',
        targetEntityType: 'Intrusion-Set',
        default: false,
      }, {
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: 'My custom view',
        path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
        targetEntityType: 'Intrusion-Set',
        default: true,
      }, {
        id: '0f65d13d-fef7-4ed7-8f40-5d53183fb983',
        name: 'Other view',
        path: 'other-view-0f65d13d-fef7-4ed7-8f40-5d53183fb983',
        targetEntityType: 'Malware',
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    const { hook } = testRenderHook(() => useCustomViews('Intrusion-Set'));
    expect(hook.result.current.customViews.map(({ name }) => name)).toStrictEqual(
      ['Basic view', 'My custom view'],
    );
  });
});
