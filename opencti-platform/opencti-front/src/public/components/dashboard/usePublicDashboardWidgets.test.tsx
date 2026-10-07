import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender, { testRenderHook } from '../../../utils/tests/test-render';
import usePublicDashboardWidgets from './usePublicDashboardWidgets';
import type { Widget } from '../../../utils/widget/widget';

// Public manifests keep one entry per dataset but strip its filters
const makeWidget = (overrides: Partial<Widget> = {}): Widget => ({
  id: 'public-widget-1',
  type: 'line',
  perspective: 'entities',
  dataSelection: [{ label: 'Reports' }],
  parameters: {},
  ...overrides,
} as unknown as Widget);

describe('usePublicDashboardWidgets', () => {
  it('should not render a broken down widget as a single total series', () => {
    const { hook } = testRenderHook(() => usePublicDashboardWidgets('public-key', {
      relativeDate: null,
      startDate: null,
      endDate: null,
    }));

    const rendered = hook.result.current.entityWidget(makeWidget({
      parameters: { breakdownBy: 'creator', interval: 'month' },
    }));
    const { getByText } = testRender(<>{rendered}</>);

    expect(getByText('Breakdowns are not supported in public dashboards')).toBeTruthy();
  });
});
