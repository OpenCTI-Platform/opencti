import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  setConfigWidget: vi.fn(),
  widget: {} as Record<string, unknown>,
  flags: ['TIME_SERIES_BREAKDOWN'],
  variables: undefined as unknown[] | undefined,
  fetchSavedFilterContent: vi.fn(),
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
        ['stix-relationship', new Map([
          ['objectMarking', definition('objectMarking', 'id', 'Marking', ['stix-relationship', 'targets'])],
          ['fromId', definition('fromId', 'id', 'Source entity', ['stix-relationship', 'targets'])],
        ])],
        ['targets', new Map([
          ['objectMarking', definition('objectMarking', 'id', 'Marking', ['targets'])],
        ])],
      ]),
    },
  }),
}));
vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => mocks.flags.includes(flag) }),
}));
vi.mock('../../../components/dashboard/DashboardVariablesContext', () => ({
  useOptionalDashboardVariableDefinitions: () => mocks.variables,
}));
vi.mock('../../../components/dashboard/dashboardVizUtils', () => ({
  fetchSavedFilterContent: mocks.fetchSavedFilterContent,
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

const relationships = {
  perspective: 'relationships',
  filters: { mode: 'and', filters: [], filterGroups: [] },
} as unknown as WidgetDataSelection;
const targets = {
  ...relationships,
  filters: { mode: 'and', filters: [{ key: 'relationship_type', values: ['targets'], operator: 'eq', mode: 'or' }], filterGroups: [] },
} as unknown as WidgetDataSelection;

const setWidget = (overrides: Record<string, unknown>) => {
  mocks.widget = { type: 'vertical-bar', perspective: 'entities', dataSelection: [reports], parameters: {}, ...overrides };
};

describe('WidgetBreakdownSelection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.flags = ['TIME_SERIES_BREAKDOWN'];
    mocks.variables = undefined;
  });

  const isDisabled = (element: HTMLElement) => element.hasAttribute('disabled') || element.getAttribute('data-disabled') !== null;

  it('offers the fields of the dataset types, then the series settings once a field is chosen', () => {
    setWidget({ parameters: { breakdownBy: 'report_types' } });
    const { getAllByRole, getByRole, getByText } = testRender(<WidgetBreakdownSelection />);

    expect(getByText('Break down by')).toBeTruthy();
    expect(getByText('Maximum number of series')).toBeTruthy();
    expect(getByText('Order')).toBeTruthy();
    expect(getByRole('switch').getAttribute('aria-checked')).toBe('false');
    expect(getByText('Include Other')).toBeTruthy();
    expect(getAllByRole('combobox')[0].textContent).toContain('Report types');
    expect(getAllByRole('combobox')[2].textContent).toContain('Highest values');
    expect(mocks.setConfigWidget).not.toHaveBeenCalled();
  });

  it('shows the stored order and other series', () => {
    setWidget({ parameters: { breakdownBy: 'report_types', breakdownOrder: 'asc', breakdownOther: true } });
    const { getAllByRole, getByRole } = testRender(<WidgetBreakdownSelection />);

    expect(getAllByRole('combobox')[2].textContent).toContain('Lowest values');
    expect(getByRole('switch').getAttribute('aria-checked')).toBe('true');
  });

  it('stores the other series choice', () => {
    setWidget({ parameters: { breakdownBy: 'report_types' } });
    const { getByRole } = testRender(<WidgetBreakdownSelection />);
    fireEvent.click(getByRole('switch'));

    expect(mocks.setConfigWidget).toHaveBeenCalledWith(expect.objectContaining({
      parameters: expect.objectContaining({ breakdownBy: 'report_types', breakdownOther: true }),
    }));
  });

  it('does not offer the order and other series without a field', () => {
    setWidget({});
    const { queryByText, queryByRole } = testRender(<WidgetBreakdownSelection />);

    expect(queryByText('Maximum number of series')).toBeNull();
    expect(queryByText('Order')).toBeNull();
    expect(queryByText('Include Other')).toBeNull();
    expect(queryByRole('switch')).toBeNull();
  });

  it('cannot be chosen with several datasets', () => {
    setWidget({ dataSelection: [reports, reports] });
    const { getAllByRole, queryByText } = testRender(<WidgetBreakdownSelection />);

    expect(isDisabled(getAllByRole('combobox')[0])).toBe(true);
    expect(queryByText('Maximum number of series')).toBeNull();
  });

  it('disables every control with several datasets', () => {
    setWidget({ dataSelection: [reports, reports], parameters: { breakdownBy: 'report_types' } });
    const { getAllByRole, getByRole } = testRender(<WidgetBreakdownSelection />);

    const comboboxes = getAllByRole('combobox');
    expect(comboboxes).toHaveLength(3);
    comboboxes.forEach((combobox) => expect(isDisabled(combobox)).toBe(true));
    expect(isDisabled(getByRole('switch'))).toBe(true);
  });

  it('keeps showing the configured field, disabled, with several datasets', () => {
    setWidget({ dataSelection: [reports, reports], parameters: { breakdownBy: 'report_types' } });
    const { getAllByRole } = testRender(<WidgetBreakdownSelection />);

    const [fieldSelect] = getAllByRole('combobox');
    expect(fieldSelect.textContent).toContain('Report types');
    expect(isDisabled(fieldSelect)).toBe(true);
  });

  it('drops a field the dataset types no longer carry, with its settings', () => {
    setWidget({ parameters: { breakdownBy: 'malware_types', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true } });
    testRender(<WidgetBreakdownSelection />);

    expect(mocks.setConfigWidget).toHaveBeenCalledWith(expect.objectContaining({
      parameters: { breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null },
    }));
  });

  describe('saved filters and dashboard variables', () => {
    const TYPE_VARIABLE_ID = '6f1c3f0e-2b7a-4c1e-9d3a-0a1b2c3d4e5f';
    const typeVariable = (restriction: Record<string, unknown>) => ({ id: TYPE_VARIABLE_ID, name: 'type', type: 'entityType', defaultValue: null, restriction });
    const byTypeVariable = {
      perspective: 'entities',
      filters: { mode: 'and', filters: [{ key: 'entity_type', values: [`$var:${TYPE_VARIABLE_ID}`], operator: 'eq', mode: 'or' }], filterGroups: [] },
    } as unknown as WidgetDataSelection;

    it('offers the fields of the types a type variable allows, and keeps a chosen one', () => {
      mocks.variables = [typeVariable({ mode: 'selection', values: ['Report'] })];
      setWidget({ dataSelection: [byTypeVariable], parameters: { breakdownBy: 'report_types' } });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);

      expect(getAllByRole('combobox')[0].textContent).toContain('Report types');
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('only offers the fields of any type for a type variable that may hold any type', () => {
      mocks.variables = [typeVariable({ mode: 'none' })];
      setWidget({ dataSelection: [byTypeVariable], parameters: { breakdownBy: 'report_types' } });
      testRender(<WidgetBreakdownSelection />);

      expect(mocks.setConfigWidget).toHaveBeenCalledWith(expect.objectContaining({
        parameters: { breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null },
      }));
    });

    it('offers the fields of the types of the saved filter, once it is read', async () => {
      let readSavedFilter: (filters: unknown) => void = () => {};
      mocks.fetchSavedFilterContent.mockReturnValue(new Promise((resolve) => {
        readSavedFilter = resolve;
      }));
      const savedFilter = { perspective: 'entities', filters_id: 'saved-filter', filters: undefined } as unknown as WidgetDataSelection;
      setWidget({ dataSelection: [savedFilter], parameters: { breakdownBy: 'report_types' } });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);

      // The types are unknown until then: the field is kept
      expect(mocks.fetchSavedFilterContent).toHaveBeenCalledWith('saved-filter');
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
      readSavedFilter(reports.filters);
      await waitFor(() => expect(getAllByRole('combobox')[0].textContent).toContain('Report types'));
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('keeps the field of a saved filter that cannot be read', async () => {
      mocks.fetchSavedFilterContent.mockResolvedValue(null);
      const savedFilter = { perspective: 'entities', filters_id: 'deleted-filter', filters: undefined } as unknown as WidgetDataSelection;
      setWidget({ dataSelection: [savedFilter], parameters: { breakdownBy: 'report_types' } });
      testRender(<WidgetBreakdownSelection />);

      await waitFor(() => expect(mocks.fetchSavedFilterContent).toHaveBeenCalled());
      await act(async () => {});
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });
  });

  describe('audits', () => {
    const logs = { perspective: 'audits', filters: { mode: 'and', filters: [], filterGroups: [] } } as unknown as WidgetDataSelection;
    const setAuditsWidget = (overrides: Record<string, unknown>) => setWidget({ perspective: 'audits', type: 'line', dataSelection: [logs], ...overrides });

    it('offers the fields of the logs and keeps a chosen one', () => {
      setAuditsWidget({ parameters: { breakdownBy: 'context_data.entity_type' } });
      const { getAllByRole, getByText } = testRender(<WidgetBreakdownSelection />);

      expect(getAllByRole('combobox')[0].textContent).toContain('Type of related entity');
      expect(getByText('Include Other')).toBeTruthy();
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('drops an entities field the logs do not have', () => {
      setAuditsWidget({ parameters: { breakdownBy: 'report_types', breakdownLimit: 20 } });
      testRender(<WidgetBreakdownSelection />);

      expect(mocks.setConfigWidget).toHaveBeenCalledWith(expect.objectContaining({
        parameters: { breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null },
      }));
    });

    it('disables every control of a dataset counting distinct values', () => {
      setAuditsWidget({ dataSelection: [{ ...logs, unique: true }] });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);

      expect(isDisabled(getAllByRole('combobox')[0])).toBe(true);
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('is shown for bars, which never count distinct values', () => {
      setAuditsWidget({ type: 'vertical-bar', dataSelection: [{ ...logs, unique: true }] });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);

      expect(isDisabled(getAllByRole('combobox')[0])).toBe(false);
    });
  });

  it('is not shown for widgets that cannot be broken down', () => {
    setWidget({ perspective: 'audits' });
    const { queryByTestId } = testRender(<WidgetBreakdownSelection />);
    expect(queryByTestId('widget-breakdown-selection')).toBeNull();
    // A relationships widget left with an entities dataset
    setWidget({ perspective: 'relationships' });
    expect(testRender(<WidgetBreakdownSelection />).queryByTestId('widget-breakdown-selection')).toBeNull();
  });

  it('is not shown, and keeps the stored breakdown, without the TIME_SERIES_BREAKDOWN feature flag', () => {
    mocks.flags = [];
    setWidget({ parameters: { breakdownBy: 'report_types', breakdownLimit: 20 } });
    expect(testRender(<WidgetBreakdownSelection />).queryByText('Break down by')).toBeNull();
    // Not even a field the dataset types do not carry is dropped
    setWidget({ parameters: { breakdownBy: 'malware_types', breakdownLimit: 20 } });
    expect(testRender(<WidgetBreakdownSelection />).queryByText('Break down by')).toBeNull();
    expect(mocks.setConfigWidget).not.toHaveBeenCalled();
  });

  describe('relationships', () => {
    const openFieldOptions = (getAllByRole: (role: string) => HTMLElement[]) => {
      const [fieldSelect] = getAllByRole('combobox');
      fireEvent.pointerDown(fieldSelect, { button: 0, ctrlKey: false, pointerType: 'mouse' });
      fireEvent.click(fieldSelect);
      return getAllByRole('option').map((option) => option.textContent);
    };

    it('offers the relationships fields the API accepts, the relationship type with several types', () => {
      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [relationships] });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);
      expect(openFieldOptions(getAllByRole)).toEqual(['None', 'Marking', 'Relationship type', 'Source type', 'Target type']);
    });

    it('offers the fields of a single relationship type, without the relationship type', () => {
      setWidget({ perspective: 'relationships', type: 'heatmap', dataSelection: [targets] });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);
      expect(openFieldOptions(getAllByRole)).toEqual(['None', 'Marking', 'Source type', 'Target type']);
    });

    it('keeps a relationships field, and drops one the relationship types no longer carry', () => {
      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [targets], parameters: { breakdownBy: 'fromTypes' } });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);
      expect(getAllByRole('combobox')[0].textContent).toContain('Source type');
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();

      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [targets], parameters: { breakdownBy: 'relationship_type' } });
      testRender(<WidgetBreakdownSelection />);
      expect(mocks.setConfigWidget).toHaveBeenCalledWith(expect.objectContaining({
        parameters: { breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null },
      }));
    });

    it('disables every control with several relationships datasets', () => {
      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [targets, targets], parameters: { breakdownBy: 'toTypes' } });
      const { getAllByRole, getByRole } = testRender(<WidgetBreakdownSelection />);
      getAllByRole('combobox').forEach((combobox) => expect(isDisabled(combobox)).toBe(true));
      expect(isDisabled(getByRole('switch'))).toBe(true);
    });
  });
});
