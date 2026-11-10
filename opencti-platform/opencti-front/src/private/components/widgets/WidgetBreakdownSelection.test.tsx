import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  setConfigWidget: vi.fn(),
  widget: {} as Record<string, unknown>,
  variables: undefined as unknown[] | undefined,
  fetchSavedFilterContent: vi.fn(),
  translations: {} as Record<string, string>,
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
        // A type without any field to break it down by
        ['Note', new Map([
          ['content', definition('content', 'string', 'Content', ['Note'])],
        ])],
      ]),
    },
  }),
}));
// The labels translated in another language, the others as in English
vi.mock('../../../components/i18n', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../components/i18n')>();
  return {
    ...original,
    useFormatter: () => {
      const formatter = original.useFormatter();
      return { ...formatter, t_i18n: (key: string) => mocks.translations[key] ?? formatter.t_i18n(key) };
    },
  };
});
vi.mock('../../../components/dashboard/DashboardVariablesContext', () => ({
  useOptionalDashboardVariableDefinitions: () => mocks.variables,
}));
vi.mock('../../../components/dashboard/dashboardVizUtils', () => ({
  fetchSavedFilterContent: mocks.fetchSavedFilterContent,
}));
vi.mock('./WidgetConfigContext', async () => {
  const { default: useResolvedWidgetBreakdown } = await import('./useResolvedWidgetBreakdown');
  const host = { kind: 'workspace' } as const;
  return {
    useWidgetConfigContext: () => ({
      config: { widget: mocks.widget },
      setConfigWidget: mocks.setConfigWidget,
      host,
    }),
    // The breakdown the editor provider derives from the edited widget
    useWidgetBreakdownState: () => useResolvedWidgetBreakdown(mocks.widget as never, host, true),
  };
});

import WidgetBreakdownSelection from './WidgetBreakdownSelection';

const reports = {
  perspective: 'entities',
  filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' }], filterGroups: [] },
} as unknown as WidgetDataSelection;
const notes = {
  ...reports,
  filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Note'], operator: 'eq', mode: 'or' }], filterGroups: [] },
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
    mocks.variables = undefined;
    mocks.translations = {};
  });

  const isDisabled = (element: HTMLElement) => element.hasAttribute('disabled') || element.getAttribute('data-disabled') !== null;
  const openOptions = (select: HTMLElement) => {
    fireEvent.pointerDown(select, { button: 0, ctrlKey: false, pointerType: 'mouse' });
    fireEvent.click(select);
    return Array.from(document.querySelectorAll('[role="option"]')).map((option) => option.textContent);
  };
  const disabledOptions = () => Array.from(document.querySelectorAll('[role="option"][data-disabled]')).map((option) => option.textContent);
  const UNREADABLE = 'The saved filter could not be read: the breakdown field cannot be checked.';

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

  it('explains the Other series with an info icon next to its switch, which the icon does not toggle', async () => {
    setWidget({ parameters: { breakdownBy: 'report_types' } });
    const { getByRole, findAllByText, user } = testRender(<WidgetBreakdownSelection />);
    const info = getByRole('button', { name: 'More information' });
    expect(info.closest('label')).toBeNull();

    await user.hover(info);
    expect((await findAllByText('Groups the entities that have none of the displayed values, including entities without a value.')).length).toBeGreaterThan(0);
    await user.click(info);
    expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    expect(getByRole('switch').getAttribute('aria-checked')).toBe('false');
  });

  it('offers the number of series of the widget, even one the editor does not offer', () => {
    // The API accepts any number from 1 to 50: written through it, or imported
    setWidget({ parameters: { breakdownBy: 'report_types', breakdownLimit: 15 } });
    const { getAllByRole } = testRender(<WidgetBreakdownSelection />);
    const limitSelect = getAllByRole('combobox')[1];

    expect(limitSelect.textContent).toContain('15');
    expect(openOptions(limitSelect)).toEqual(['5', '10', '15', '20', '50']);
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

  it('shows none for a field the dataset types no longer carry, dropped on submit only', () => {
    setWidget({ parameters: { breakdownBy: 'malware_types', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true } });
    const { getAllByRole, queryByText } = testRender(<WidgetBreakdownSelection />);

    expect(getAllByRole('combobox')).toHaveLength(1);
    expect(getAllByRole('combobox')[0].textContent).toContain('None');
    expect(queryByText('Maximum number of series')).toBeNull();
    expect(mocks.setConfigWidget).not.toHaveBeenCalled();
  });

  it('keeps and lists the entity type of a dataset of a single type, which the API accepts', () => {
    setWidget({ parameters: { breakdownBy: 'entity_type', breakdownLimit: 20 } });
    const { getAllByRole, getByText } = testRender(<WidgetBreakdownSelection />);

    expect(getAllByRole('combobox')[0].textContent).toContain('Entity type');
    expect(getByText('Maximum number of series')).toBeTruthy();
    expect(openOptions(getAllByRole('combobox')[0])).toEqual(['None', 'Author', 'Report types', 'Entity type']);
    expect(disabledOptions()).toEqual([]);
    expect(mocks.setConfigWidget).not.toHaveBeenCalled();
  });

  it('is not shown for a dataset without any field to break it down by, unless one is kept', () => {
    setWidget({ dataSelection: [notes] });
    expect(testRender(<WidgetBreakdownSelection />).queryByTestId('widget-breakdown-selection')).toBeNull();
    setWidget({ dataSelection: [notes], parameters: { breakdownBy: 'entity_type' } });
    const { getAllByRole } = testRender(<WidgetBreakdownSelection />);
    expect(getAllByRole('combobox')[0].textContent).toContain('Entity type');
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
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);

      expect(getAllByRole('combobox')[0].textContent).toContain('None');
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('keeps the field while the saved filter is read, listed apart and disabled, then among the fields it offers', async () => {
      let readSavedFilter: (filters: unknown) => void = () => {};
      mocks.fetchSavedFilterContent.mockReturnValue(new Promise((resolve) => {
        readSavedFilter = resolve;
      }));
      const savedFilter = { perspective: 'entities', filters_id: 'saved-filter', filters: undefined } as unknown as WidgetDataSelection;
      setWidget({ dataSelection: [savedFilter], parameters: { breakdownBy: 'report_types', breakdownLimit: 20 } });
      const { getAllByRole, getByText, queryByText } = testRender(<WidgetBreakdownSelection />);

      // The types are unknown until then: the field is kept, with its settings
      expect(mocks.fetchSavedFilterContent).toHaveBeenCalledWith('saved-filter');
      expect(getAllByRole('combobox')[0].textContent).toContain('Report types');
      expect(getByText('Maximum number of series')).toBeTruthy();
      expect(queryByText(UNREADABLE)).toBeNull();
      // The fields of any dataset, the field of the widget apart
      expect(openOptions(getAllByRole('combobox')[0])).toEqual(['None', 'Entity type', 'Report types']);
      expect(disabledOptions()).toEqual(['Report types']);
      fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });

      await act(async () => readSavedFilter(reports.filters));
      expect(getAllByRole('combobox')[0].textContent).toContain('Report types');
      expect(openOptions(getAllByRole('combobox')[0])).toEqual(['None', 'Author', 'Report types']);
      expect(disabledOptions()).toEqual([]);
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('keeps the field of a saved filter that cannot be read, and says it cannot be checked', async () => {
      mocks.fetchSavedFilterContent.mockResolvedValue(null);
      const savedFilter = { perspective: 'entities', filters_id: 'deleted-filter', filters: undefined } as unknown as WidgetDataSelection;
      setWidget({ dataSelection: [savedFilter], parameters: { breakdownBy: 'report_types' } });
      const { getAllByRole, findByText } = testRender(<WidgetBreakdownSelection />);

      expect(await findByText(UNREADABLE)).toBeTruthy();
      expect(getAllByRole('combobox')[0].textContent).toContain('Report types');
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('says nothing of a saved filter that cannot be read while no field is chosen', async () => {
      mocks.fetchSavedFilterContent.mockResolvedValue(null);
      const savedFilter = { perspective: 'entities', filters_id: 'deleted-filter', filters: undefined } as unknown as WidgetDataSelection;
      setWidget({ dataSelection: [savedFilter] });
      const { getByText, queryByText } = testRender(<WidgetBreakdownSelection />);

      await waitFor(() => expect(mocks.fetchSavedFilterContent).toHaveBeenCalledWith('deleted-filter'));
      // The read has failed once its promise is settled
      await act(async () => {});
      expect(getByText('Break down by')).toBeTruthy();
      expect(queryByText(UNREADABLE)).toBeNull();
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

    it('shows none for an entities field the logs do not have', () => {
      setAuditsWidget({ parameters: { breakdownBy: 'report_types', breakdownLimit: 20 } });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);

      expect(getAllByRole('combobox')[0].textContent).toContain('None');
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
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

  describe('relationships', () => {
    const openFieldOptions = (getAllByRole: (role: string) => HTMLElement[]) => openOptions(getAllByRole('combobox')[0]);

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

    it('orders the fields as they read in the language of the user', () => {
      mocks.translations = {
        None: 'Aucun',
        Marking: 'Marquage',
        'Relationship type': 'Type de relation',
        'Source type': 'Type de source',
        'Target type': 'Type de cible',
      };
      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [relationships] });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);
      expect(openFieldOptions(getAllByRole)).toEqual(['Aucun', 'Marquage', 'Type de cible', 'Type de relation', 'Type de source']);
    });

    it('keeps a relationships field, and the relationship type of a single relationship type', () => {
      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [targets], parameters: { breakdownBy: 'fromTypes' } });
      const first = testRender(<WidgetBreakdownSelection />);
      expect(first.getAllByRole('combobox')[0].textContent).toContain('Source type');
      first.unmount();

      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [targets], parameters: { breakdownBy: 'relationship_type' } });
      const { getAllByRole } = testRender(<WidgetBreakdownSelection />);
      expect(getAllByRole('combobox')[0].textContent).toContain('Relationship type');
      expect(openOptions(getAllByRole('combobox')[0])).toEqual(['None', 'Marking', 'Source type', 'Target type', 'Relationship type']);
      expect(mocks.setConfigWidget).not.toHaveBeenCalled();
    });

    it('cannot be chosen with several relationships datasets', () => {
      setWidget({ perspective: 'relationships', type: 'line', dataSelection: [targets, targets] });
      const { getAllByRole, queryByRole } = testRender(<WidgetBreakdownSelection />);
      expect(getAllByRole('combobox')).toHaveLength(1);
      expect(isDisabled(getAllByRole('combobox')[0])).toBe(true);
      expect(queryByRole('switch')).toBeNull();
    });
  });
});
