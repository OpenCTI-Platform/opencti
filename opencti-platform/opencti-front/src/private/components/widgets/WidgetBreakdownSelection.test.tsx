import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  setConfigWidget: vi.fn(),
  widget: {} as Record<string, unknown>,
}));

const definition = (filterKey: string, type: string, label: string, subEntityTypes: string[]): FilterDefinition => ({
  filterKey, type, label, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
});

vi.mock('../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useAuth')>()),
  default: () => ({
    schema: {
      filterKeysSchema: new Map([
        ['Report', new Map([
          ['createdBy', definition('createdBy', 'id', 'Author', ['Report'])],
          ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
        ])],
      ]),
    },
  }),
}));
vi.mock('./WidgetConfigContext', () => ({
  useWidgetConfigContext: () => ({
    config: { widget: mocks.widget },
    setConfigWidget: mocks.setConfigWidget,
    host: { kind: 'workspace' },
  }),
}));

import WidgetBreakdownSelection from './WidgetBreakdownSelection';

const reports = {
  perspective: 'entities',
  filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' }], filterGroups: [] },
} as unknown as WidgetDataSelection;

const setWidget = (overrides: Record<string, unknown>) => {
  mocks.widget = { type: 'vertical-bar', perspective: 'entities', dataSelection: [reports], parameters: {}, ...overrides };
};

describe('WidgetBreakdownSelection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('offers the fields of the dataset types, then the number of series once a field is chosen', () => {
    setWidget({ parameters: { breakdownBy: 'report_types' } });
    const { getAllByRole, getByText } = testRender(<WidgetBreakdownSelection />);

    expect(getByText('Break down by')).toBeTruthy();
    expect(getByText('Maximum number of series')).toBeTruthy();
    expect(getAllByRole('combobox')[0].textContent).toContain('Report types');
    expect(mocks.setConfigWidget).not.toHaveBeenCalled();
  });

  it('cannot be chosen with several datasets', () => {
    setWidget({ dataSelection: [reports, reports] });
    const { getAllByRole, queryByText } = testRender(<WidgetBreakdownSelection />);

    expect(getAllByRole('combobox')[0].hasAttribute('disabled') || getAllByRole('combobox')[0].getAttribute('data-disabled') !== null).toBe(true);
    expect(queryByText('Maximum number of series')).toBeNull();
  });

  it('drops a field the dataset types no longer carry', () => {
    setWidget({ parameters: { breakdownBy: 'malware_types' } });
    testRender(<WidgetBreakdownSelection />);

    expect(mocks.setConfigWidget).toHaveBeenCalledWith(expect.objectContaining({
      parameters: expect.objectContaining({ breakdownBy: null }),
    }));
  });

  it('is not shown for widgets that cannot be broken down', () => {
    setWidget({ perspective: 'relationships' });
    const { queryByTestId } = testRender(<WidgetBreakdownSelection />);
    expect(queryByTestId('widget-breakdown-selection')).toBeNull();
  });
});
