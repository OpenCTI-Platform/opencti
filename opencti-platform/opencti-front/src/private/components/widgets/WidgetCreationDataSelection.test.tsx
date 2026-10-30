import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  widget: {} as Record<string, unknown>,
  host: { kind: 'workspace' } as Record<string, unknown>,
  flags: ['TIME_SERIES_BREAKDOWN'],
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
        ['Report', new Map([['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])]])],
        ['Malware', new Map([['malware_types', definition('malware_types', 'vocabulary', 'Malware types', ['Malware'])]])],
        ['stix-relationship', new Map([['objectMarking', definition('objectMarking', 'id', 'Marking', ['stix-relationship', 'targets', 'uses'])]])],
        ['targets', new Map([['objectMarking', definition('objectMarking', 'id', 'Marking', ['targets'])]])],
        ['uses', new Map([['usage_types', definition('usage_types', 'vocabulary', 'Usage types', ['uses'])]])],
      ]),
    },
  }),
}));
vi.mock('../../../components/dashboard/dashboardVizUtils', () => ({
  fetchSavedFilterContent: mocks.fetchSavedFilterContent,
}));

vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => mocks.flags.includes(flag) }),
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
const ofType = (perspective: string, key: string, type: string) => ({
  label: '',
  perspective,
  filters: { mode: 'and', filters: [{ key, values: [type], operator: 'eq', mode: 'or' }], filterGroups: [] },
} as unknown as WidgetDataSelection);

describe('WidgetCreationDataSelection of a relationships widget', () => {
  beforeEach(() => {
    mocks.host = { kind: 'workspace' };
    mocks.flags = ['TIME_SERIES_BREAKDOWN'];
  });

  it('says a single dataset can be broken down, and lets more datasets be added without breakdown', () => {
    setWidget({});
    const { getByText, getByRole } = testRender(<WidgetCreationDataSelection />);
    expect(getByText(INFO)).toBeTruthy();
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(false);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(false);
  });

  it('offers the breakdown in a custom view too', () => {
    mocks.host = { kind: 'custom-view', customViewTargetEntityType: 'Report' };
    setWidget({});
    expect(testRender(<WidgetCreationDataSelection />).getByText(INFO)).toBeTruthy();
  });

  it('cannot add another dataset to a broken down widget', () => {
    setWidget({ parameters: { breakdownBy: 'toTypes' } });
    const { getByRole } = testRender(<WidgetCreationDataSelection />);
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(true);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(true);
  });

  it('lets datasets be added next to a field the relationship types no longer offer, which the parameters step drops', () => {
    setWidget({ dataSelection: [ofType('relationships', 'relationship_type', 'uses')], parameters: { breakdownBy: 'usage_types' } });
    const locked = testRender(<WidgetCreationDataSelection />);
    expect(isDisabled(locked.getByRole('button', { name: 'Relationships' }))).toBe(true);
    locked.unmount();
    setWidget({ dataSelection: [ofType('relationships', 'relationship_type', 'targets')], parameters: { breakdownBy: 'usage_types' } });
    const { getByRole } = testRender(<WidgetCreationDataSelection />);
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(false);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(false);
  });

  it('says nothing about the breakdown when it is not available', () => {
    setWidget({ type: 'donut' });
    expect(testRender(<WidgetCreationDataSelection />).queryByText(INFO)).toBeNull();
    setWidget({ dataSelection: [relationships, relationships] });
    expect(testRender(<WidgetCreationDataSelection />).queryByText(INFO)).toBeNull();
    mocks.host = { kind: 'fintelTemplate', fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' };
    setWidget({});
    expect(testRender(<WidgetCreationDataSelection />).queryByText(INFO)).toBeNull();
  });

  it('says nothing about the breakdown and lets datasets be added, whatever breakdown is stored, without the TIME_SERIES_BREAKDOWN feature flag', () => {
    mocks.flags = [];
    setWidget({ parameters: { breakdownBy: 'toTypes' } });
    const { queryByText, getByRole } = testRender(<WidgetCreationDataSelection />);
    expect(queryByText(INFO)).toBeNull();
    expect(isDisabled(getByRole('button', { name: 'Relationships' }))).toBe(false);
    expect(isDisabled(getByRole('button', { name: 'Entities' }))).toBe(false);
  });
});

describe('WidgetCreationDataSelection of a broken down widget', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.host = { kind: 'workspace' };
    mocks.flags = ['TIME_SERIES_BREAKDOWN'];
  });

  const isAddDisabled = () => {
    const { getByRole, unmount } = testRender(<WidgetCreationDataSelection />);
    const disabled = isDisabled(getByRole('button', { name: 'Add' }));
    unmount();
    return disabled;
  };

  it('cannot add an entities dataset next to a field of the entity type', () => {
    setWidget({ perspective: 'entities', dataSelection: [ofType('entities', 'entity_type', 'Report')], parameters: { breakdownBy: 'report_types' } });
    expect(isAddDisabled()).toBe(true);
  });

  it('lets an entities dataset be added once the type filter no longer offers the field', () => {
    // Report types chosen, then the type filter changed to Malware in the filters step
    setWidget({ perspective: 'entities', dataSelection: [ofType('entities', 'entity_type', 'Malware')], parameters: { breakdownBy: 'report_types' } });
    expect(isAddDisabled()).toBe(false);
  });

  it('cannot add an audits dataset next to a field of the logs, only next to one they do not have', () => {
    const logs = { label: '', perspective: 'audits', filters: { mode: 'and', filters: [], filterGroups: [] } };
    setWidget({ perspective: 'audits', dataSelection: [logs], parameters: { breakdownBy: 'event_type' } });
    expect(isAddDisabled()).toBe(true);
    setWidget({ perspective: 'audits', dataSelection: [logs], parameters: { breakdownBy: 'report_types' } });
    expect(isAddDisabled()).toBe(false);
  });

  it('keeps the datasets locked until the saved filter is read, as the parameters step keeps the field', async () => {
    let readSavedFilter: (filters: unknown) => void = () => {};
    mocks.fetchSavedFilterContent.mockReturnValue(new Promise((resolve) => {
      readSavedFilter = resolve;
    }));
    const savedFilter = { label: '', perspective: 'entities', filters_id: 'saved-filter', filters: undefined };
    setWidget({ perspective: 'entities', dataSelection: [savedFilter], parameters: { breakdownBy: 'report_types' } });
    const { getByRole } = testRender(<WidgetCreationDataSelection />);

    expect(isDisabled(getByRole('button', { name: 'Add' }))).toBe(true);
    readSavedFilter(ofType('entities', 'entity_type', 'Malware').filters);
    await waitFor(() => expect(isDisabled(getByRole('button', { name: 'Add' }))).toBe(false));
  });
});
