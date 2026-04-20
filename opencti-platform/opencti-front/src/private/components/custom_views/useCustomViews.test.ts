import { describe, it, expect } from 'vitest';
import { useCustomViews } from './useCustomViews';
import { createMockUserContext, testRenderHook } from '../../../utils/tests/test-render';

describe('useCustomViews', () => {
  it('provides the list of custom views sorted by name', () => {
    const { hook } = testRenderHook(() => useCustomViews('Intrusion-Set'), {
      userContext: createMockUserContext({
        customViews: [{
          entity_type: 'Intrusion-Set',
          custom_views_info: [{
            id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
            name: 'My custom view',
            path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
          }, {
            id: 'e8170a92-344d-4b17-815b-7eb2ec26430c',
            name: 'Basic view',
            path: 'basic-view-e8170a92344d4b17815b7eb2ec26430c',
          }],
        }],
      }),
    });
    expect(hook.result.current.customViews.map(({ name }) => name)).toStrictEqual(
      ['Basic view', 'My custom view'],
    );
  });
});
