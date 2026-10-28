import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import type { WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  widget: {} as Record<string, unknown>,
  host: { kind: 'workspace' } as Record<string, unknown>,
}));

vi.mock('./WidgetConfigContext', () => ({
  useWidgetConfigContext: () => ({
    config: { widget: mocks.widget },
    host: mocks.host,
    setStep: vi.fn(),
    setDataSelection: vi.fn(),
    setDataSelectionWithIndex: vi.fn(),
  }),
}));
vi.mock('@components/widgets/WidgetFilters', () => ({
  default: () => <div data-testid="widget-filters" />,
}));

import WidgetCreationDataSelection from './WidgetCreationDataSelection';

const relationships = {
  label: '',
  perspective: 'relationships',
  filters: { mode: 'and', filters: [], filterGroups: [] },
} as unknown as WidgetDataSelection;

const INFO = 'You can break this dataset down into one series per field value in the Parameters step.';

const setWidget = (overrides: Record<string, unknown>) => {
  mocks.widget = { type: 'line', perspective: 'relationships', dataSelection: [relationships], parameters: {}, ...overrides };
};
const isDisabled = (element: HTMLElement) => element.hasAttribute('disabled') || element.getAttribute('aria-disabled') === 'true';

describe('WidgetCreationDataSelection of a relationships widget', () => {
  beforeEach(() => {
    mocks.host = { kind: 'workspace' };
  });

  it('says a single dataset can be broken down, and lets more datasets be added without breakdown', () => {
    setWidget({});
    const { getByText, getByRole } = testRender(<WidgetCreationDataSelection />);
    expect(getByText(INFO)).toBeTruthy();
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(false);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(false);
  });

  it('cannot add another dataset to a broken down widget', () => {
    setWidget({ parameters: { breakdownBy: 'toTypes' } });
    const { getByRole } = testRender(<WidgetCreationDataSelection />);
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(true);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(true);
  });

  it('says nothing about the breakdown when it is not available', () => {
    setWidget({ type: 'donut' });
    expect(testRender(<WidgetCreationDataSelection />).queryByText(INFO)).toBeNull();
    setWidget({ dataSelection: [relationships, relationships] });
    expect(testRender(<WidgetCreationDataSelection />).queryByText(INFO)).toBeNull();
    mocks.host = { kind: 'custom-view', customViewTargetEntityType: 'Report' };
    setWidget({});
    expect(testRender(<WidgetCreationDataSelection />).queryByText(INFO)).toBeNull();
  });
});
