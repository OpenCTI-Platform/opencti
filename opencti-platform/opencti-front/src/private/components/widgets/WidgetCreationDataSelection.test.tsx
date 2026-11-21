import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  widget: {} as Record<string, unknown>,
  host: { kind: 'workspace' } as Record<string, unknown>,
  fetchSavedFilterContent: vi.fn(),
  fetchTimeSeriesBreakdownFields: vi.fn(),
}));

const definition = (filterKey: string, type: string, label: string, subEntityTypes: string[]): FilterDefinition => ({
  filterKey, type, label, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
});

vi.mock('../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useAuth')>()),
  default: () => ({
    schema: {
      filterKeysSchema: new Map([
        ['Report', new Map([['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])]])],
        ['Malware', new Map([['malware_types', definition('malware_types', 'vocabulary', 'Malware types', ['Malware'])]])],
        ['stix-relationship', new Map([['objectMarking', definition('objectMarking', 'id', 'Marking', ['stix-relationship', 'targets', 'uses'])]])],
        ['targets', new Map([['objectMarking', definition('objectMarking', 'id', 'Marking', ['targets'])]])],
        ['uses', new Map([['usage_types', definition('usage_types', 'vocabulary', 'Usage types', ['uses'])]])],
        ['DraftWorkspace', new Map([['creator_id', definition('creator_id', 'id', 'Creators', ['DraftWorkspace'])]])],
      ]),
    },
  }),
}));
vi.mock('../../../components/dashboard/dashboardVizUtils', () => ({
  fetchSavedFilterContent: mocks.fetchSavedFilterContent,
  fetchTimeSeriesBreakdownFields: mocks.fetchTimeSeriesBreakdownFields,
}));

vi.mock('./WidgetConfigContext', async () => {
  const { default: useResolvedWidgetBreakdown } = await import('./useResolvedWidgetBreakdown');
  return {
    useWidgetConfigContext: () => ({
      config: { widget: mocks.widget },
      host: mocks.host,
      setStep: vi.fn(),
      setDataSelection: vi.fn(),
      setDataSelectionWithIndex: vi.fn(),
    }),
    // The breakdown the editor provider derives from the edited widget
    useWidgetBreakdownState: () => useResolvedWidgetBreakdown(mocks.widget as never, mocks.host as never, true),
  };
});
vi.mock('@components/widgets/WidgetFilters', () => ({
  default: () => <div data-testid="widget-filters" />,
}));

import WidgetCreationDataSelection from './WidgetCreationDataSelection';

// The fields the API offers (timeSeriesBreakdownFields) for the perspectives and types of these tests
const API_FIELDS: Record<string, string[]> = {
  'entities:Report': ['report_types'],
  'entities:Malware': ['malware_types'],
  'relationships:': ['objectMarking', 'fromTypes', 'toTypes', 'relationship_type'],
  'relationships:targets': ['objectMarking', 'fromTypes', 'toTypes'],
  'relationships:uses': ['usage_types', 'fromTypes', 'toTypes'],
  'audits:': ['event_type', 'event_scope', 'user_id', 'group_ids', 'organization_ids', 'entity_type', 'context_data.entity_type'],
};
const readApiFields = async (perspective: string, types: string[]) => API_FIELDS[`${perspective}:${types.join(',')}`] ?? [];
const readFieldsFromApi = () => {
  mocks.fetchTimeSeriesBreakdownFields.mockReset();
  mocks.fetchTimeSeriesBreakdownFields.mockImplementation(readApiFields);
};
// Rendered once the fields of the dataset are read
const renderDataSelection = async () => {
  const rendered = testRender(<WidgetCreationDataSelection />);
  await act(async () => {});
  return rendered;
};

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
const ofType = (perspective: string, key: string, type: string) => ({
  label: '',
  perspective,
  filters: { mode: 'and', filters: [{ key, values: [type], operator: 'eq', mode: 'or' }], filterGroups: [] },
} as unknown as WidgetDataSelection);

describe('WidgetCreationDataSelection of a relationships widget', () => {
  beforeEach(() => {
    mocks.host = { kind: 'workspace' };
    readFieldsFromApi();
  });

  it('says a single dataset can be broken down, and lets more datasets be added without breakdown', async () => {
    setWidget({});
    const { getByText, getByRole } = await renderDataSelection();
    expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenCalledWith('relationships', []);
    expect(getByText(INFO)).toBeTruthy();
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(false);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(false);
  });

  it('offers the breakdown in a custom view too', async () => {
    mocks.host = { kind: 'custom-view', customViewTargetEntityType: 'Report' };
    setWidget({});
    expect((await renderDataSelection()).getByText(INFO)).toBeTruthy();
  });

  it('cannot add another dataset to a broken down widget, already broken down', async () => {
    setWidget({ parameters: { breakdownBy: 'toTypes' } });
    const { getByRole, queryByText } = await renderDataSelection();
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(true);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(true);
    expect(queryByText(INFO)).toBeNull();
  });

  it('lets datasets be added next to a field the relationship types no longer offer, dropped on submit', async () => {
    setWidget({ dataSelection: [ofType('relationships', 'relationship_type', 'uses')], parameters: { breakdownBy: 'usage_types' } });
    const locked = await renderDataSelection();
    expect(isDisabled(locked.getByRole('button', { name: 'Relationships' }))).toBe(true);
    locked.unmount();
    setWidget({ dataSelection: [ofType('relationships', 'relationship_type', 'targets')], parameters: { breakdownBy: 'usage_types' } });
    const { getByRole } = await renderDataSelection();
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(false);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(false);
  });

  it('says nothing about the breakdown until the fields of the dataset are read, nor without any', async () => {
    let readFields: (keys: string[] | null) => void = () => {};
    mocks.fetchTimeSeriesBreakdownFields.mockReturnValue(new Promise((resolve) => {
      readFields = resolve;
    }));
    setWidget({});
    const { queryByText, unmount } = await renderDataSelection();
    expect(queryByText(INFO)).toBeNull();
    await act(async () => readFields(['objectMarking']));
    expect(queryByText(INFO)).toBeTruthy();
    unmount();

    mocks.fetchTimeSeriesBreakdownFields.mockResolvedValue([]);
    expect((await renderDataSelection()).queryByText(INFO)).toBeNull();
  });

  it('keeps saying the dataset can be broken down while the fields of its next types are read, only when it said so', async () => {
    const pending: Record<string, (keys: string[] | null) => void> = {};
    // The fields of the uses are read at once, the others when the test says so
    const readOnDemand = (types: string[]) => new Promise((resolve) => {
      pending[types.join(',')] = resolve;
    });
    mocks.fetchTimeSeriesBreakdownFields.mockImplementation((perspective: string, types: string[]) => (
      types[0] === 'uses' ? readApiFields(perspective, types) : readOnDemand(types)
    ));
    setWidget({ dataSelection: [ofType('relationships', 'relationship_type', 'uses')] });
    const { queryByText, rerender } = await renderDataSelection();
    expect(queryByText(INFO)).toBeTruthy();

    // The type filter changed: the fields of the new types are read
    setWidget({ dataSelection: [ofType('relationships', 'relationship_type', 'targets')] });
    rerender(<WidgetCreationDataSelection />);
    expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenLastCalledWith('relationships', ['targets']);
    expect(queryByText(INFO)).toBeTruthy();
    // ...without any to break them down by
    await act(async () => pending.targets([]));
    expect(queryByText(INFO)).toBeNull();

    // Not said while the fields of the next ones are read, as it was not said for these
    setWidget({ dataSelection: [ofType('relationships', 'relationship_type', 'related-to')] });
    rerender(<WidgetCreationDataSelection />);
    expect(queryByText(INFO)).toBeNull();
    await act(async () => pending['related-to'](['objectMarking']));
    expect(queryByText(INFO)).toBeTruthy();
  });

  it('says nothing about the breakdown when it is not available', async () => {
    setWidget({ type: 'donut' });
    expect((await renderDataSelection()).queryByText(INFO)).toBeNull();
    setWidget({ dataSelection: [relationships, relationships] });
    expect((await renderDataSelection()).queryByText(INFO)).toBeNull();
    mocks.host = { kind: 'fintelTemplate', fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' };
    setWidget({});
    expect((await renderDataSelection()).queryByText(INFO)).toBeNull();
  });
});

describe('WidgetCreationDataSelection of a broken down widget', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.host = { kind: 'workspace' };
    readFieldsFromApi();
  });

  const isAddDisabled = async () => {
    const { getByRole, unmount } = await renderDataSelection();
    const disabled = isDisabled(getByRole('button', { name: 'Add' }));
    unmount();
    return disabled;
  };

  it('cannot add an entities dataset next to a field of the entity type', async () => {
    setWidget({ perspective: 'entities', dataSelection: [ofType('entities', 'entity_type', 'Report')], parameters: { breakdownBy: 'report_types' } });
    expect(await isAddDisabled()).toBe(true);
  });

  it('lets an entities dataset be added once the type filter no longer offers the field', async () => {
    // Report types chosen, then the type filter changed to Malware in the filters step
    setWidget({ perspective: 'entities', dataSelection: [ofType('entities', 'entity_type', 'Malware')], parameters: { breakdownBy: 'report_types' } });
    expect(await isAddDisabled()).toBe(false);
  });

  it('cannot add an audits dataset next to a field of the logs, only next to one they do not have', async () => {
    const logs = { label: '', perspective: 'audits', filters: { mode: 'and', filters: [], filterGroups: [] } };
    setWidget({ perspective: 'audits', dataSelection: [logs], parameters: { breakdownBy: 'event_type' } });
    expect(await isAddDisabled()).toBe(true);
    setWidget({ perspective: 'audits', dataSelection: [logs], parameters: { breakdownBy: 'report_types' } });
    expect(await isAddDisabled()).toBe(false);
  });

  it('keeps the datasets locked until the saved filter is read, as the parameters step keeps the field', async () => {
    let readSavedFilter: (filters: unknown) => void = () => {};
    mocks.fetchSavedFilterContent.mockReturnValue(new Promise((resolve) => {
      readSavedFilter = resolve;
    }));
    const savedFilter = { label: '', perspective: 'entities', filters_id: 'saved-filter', filters: undefined };
    setWidget({ perspective: 'entities', dataSelection: [savedFilter], parameters: { breakdownBy: 'report_types' } });
    const { getByRole } = await renderDataSelection();

    expect(isDisabled(getByRole('button', { name: 'Add' }))).toBe(true);
    readSavedFilter(ofType('entities', 'entity_type', 'Malware').filters);
    await waitFor(() => expect(isDisabled(getByRole('button', { name: 'Add' }))).toBe(false));
  });

  it('keeps the datasets locked while the fields of the dataset are read, and when they cannot be', async () => {
    let readFields: (keys: string[] | null) => void = () => {};
    mocks.fetchTimeSeriesBreakdownFields.mockReturnValue(new Promise((resolve) => {
      readFields = resolve;
    }));
    setWidget({ perspective: 'entities', dataSelection: [ofType('entities', 'entity_type', 'Malware')], parameters: { breakdownBy: 'report_types' } });
    const { getByRole, unmount } = await renderDataSelection();

    expect(isDisabled(getByRole('button', { name: 'Add' }))).toBe(true);
    await act(async () => readFields(['malware_types']));
    expect(isDisabled(getByRole('button', { name: 'Add' }))).toBe(false);
    unmount();

    mocks.fetchTimeSeriesBreakdownFields.mockResolvedValue(null);
    expect(await isAddDisabled()).toBe(true);
  });
});

describe('WidgetCreationDataSelection of a dataset read from a saved filter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.host = { kind: 'workspace' };
    readFieldsFromApi();
  });

  const savedFilter = { label: '', perspective: 'entities', filters_id: 'saved-filter', filters: undefined };

  it('says the dataset can be broken down once the saved filter is read', async () => {
    let readSavedFilter: (filters: unknown) => void = () => {};
    mocks.fetchSavedFilterContent.mockReturnValue(new Promise((resolve) => {
      readSavedFilter = resolve;
    }));
    setWidget({ perspective: 'entities', dataSelection: [savedFilter] });
    const { queryByText, findByText } = await renderDataSelection();

    expect(queryByText(INFO)).toBeNull();
    readSavedFilter(ofType('entities', 'entity_type', 'Report').filters);
    expect(await findByText(INFO)).toBeTruthy();
  });

  it('says nothing about the breakdown of draft workspaces, and lets datasets be added', async () => {
    mocks.fetchSavedFilterContent.mockResolvedValue(ofType('entities', 'entity_type', 'DraftWorkspace').filters);
    setWidget({ perspective: 'entities', dataSelection: [savedFilter], parameters: { breakdownBy: 'creator_id' } });
    const { queryByText, getByRole } = await renderDataSelection();

    await waitFor(() => expect(isDisabled(getByRole('button', { name: 'Add' }))).toBe(false));
    expect(queryByText(INFO)).toBeNull();
    expect(mocks.fetchTimeSeriesBreakdownFields).not.toHaveBeenCalled();
  });
});
