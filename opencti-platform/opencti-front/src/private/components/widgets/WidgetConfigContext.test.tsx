import React from 'react';
import { act } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import type { Widget } from '../../../utils/widget/widget';

const flags = vi.hoisted(() => ({ enabled: ['TIME_SERIES_BREAKDOWN'] }));
vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => flags.enabled.includes(flag) }),
}));

import { useWidgetConfigContext, WidgetConfigProvider } from './WidgetConfigContext';

type WidgetConfigContext = ReturnType<typeof useWidgetConfigContext>;

const breakdown = { breakdownBy: 'entity_type', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true };
const brokenDownLine = {
  id: 'widget-1',
  type: 'line',
  perspective: 'entities',
  dataSelection: [{ filters: { mode: 'and', filters: [], filterGroups: [] } }],
  parameters: { title: 'Reports', ...breakdown },
} as unknown as Widget;

const captured: { context?: WidgetConfigContext } = {};
const CaptureContext = () => {
  captured.context = useWidgetConfigContext();
  return null;
};

const renderProvider = (initialWidget = brokenDownLine) => testRender(
  <WidgetConfigProvider host={{ kind: 'workspace' }} disabledSteps={[]} initialWidget={initialWidget} initialVariableName={undefined} open>
    <CaptureContext />
  </WidgetConfigProvider>,
);

// A donut cannot be broken down
const changeIntoDonut = () => act(() => {
  const { config, setConfigWidget } = captured.context as WidgetConfigContext;
  setConfigWidget({ ...config.widget, type: 'donut' });
});

describe('WidgetConfigProvider', () => {
  beforeEach(() => {
    flags.enabled = ['TIME_SERIES_BREAKDOWN'];
    captured.context = undefined;
  });

  it('drops the breakdown of a widget that can no longer be broken down', () => {
    renderProvider();
    changeIntoDonut();
    expect(captured.context?.config.widget.parameters).toEqual({
      title: 'Reports', breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null,
    });
  });

  it('drops the stored breakdown of a widget with several datasets once the filters step stores them, before the parameters step', () => {
    const [selection] = brokenDownLine.dataSelection;
    renderProvider({ ...brokenDownLine, dataSelection: [selection, selection] });
    // Opened on the filters step, whose datasets each store their filters when mounted (WidgetFilters)
    expect(captured.context?.step).toBe(2);
    act(() => captured.context?.setDataSelectionWithIndex(selection, 0));
    expect(captured.context?.config.widget.parameters).toEqual({
      title: 'Reports', breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null,
    });
  });

  it('keeps the stored breakdown as it is without the TIME_SERIES_BREAKDOWN feature flag', () => {
    flags.enabled = [];
    renderProvider();
    changeIntoDonut();
    expect(captured.context?.config.widget.type).toBe('donut');
    expect(captured.context?.config.widget.parameters).toEqual({ title: 'Reports', ...breakdown });
  });
});
