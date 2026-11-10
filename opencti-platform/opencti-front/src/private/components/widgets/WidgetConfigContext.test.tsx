import React from 'react';
import { act } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Widget, WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  flags: ['TIME_SERIES_BREAKDOWN'],
  fetchSavedFilterContent: vi.fn(),
  fetchTimeSeriesBreakdownFields: vi.fn(),
}));
vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => mocks.flags.includes(flag) }),
}));
vi.mock('../../../components/dashboard/dashboardVizUtils', () => ({
  fetchSavedFilterContent: mocks.fetchSavedFilterContent,
  fetchTimeSeriesBreakdownFields: mocks.fetchTimeSeriesBreakdownFields,
}));

import { useWidgetBreakdownState, useWidgetConfigContext, WidgetConfigProvider } from './WidgetConfigContext';
import useWidgetConfigValidateForm from './useWidgetConfigValidateForm';

type WidgetConfigContext = ReturnType<typeof useWidgetConfigContext>;

const definition = (filterKey: string, type: string, label: string, subEntityTypes: string[]): FilterDefinition => ({
  filterKey, type, label, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
});
const userContext = createMockUserContext({
  schema: {
    filterKeysSchema: new Map([
      ['Report', new Map([['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])]])],
      ['Malware', new Map([['malware_types', definition('malware_types', 'vocabulary', 'Malware types', ['Malware'])]])],
    ]),
  },
});

const ofType = (type: string) => ({ mode: 'and', filters: [{ key: 'entity_type', values: [type], operator: 'eq', mode: 'or' }], filterGroups: [] });
const reports = { perspective: 'entities', filters: ofType('Report') } as unknown as WidgetDataSelection;
const breakdown = { breakdownBy: 'report_types', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true };
const NO_BREAKDOWN = { breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null };
const brokenDownLine = {
  id: 'widget-1',
  type: 'line',
  perspective: 'entities',
  dataSelection: [reports],
  parameters: { title: 'Reports', ...breakdown },
} as unknown as Widget;

const captured: { context?: WidgetConfigContext; breakdown?: ReturnType<typeof useWidgetBreakdownState>; isFormValid?: boolean } = {};
const CaptureContext = () => {
  captured.context = useWidgetConfigContext();
  captured.breakdown = useWidgetBreakdownState();
  captured.isFormValid = useWidgetConfigValidateForm().isFormValid;
  return null;
};

const provider = (initialWidget: Widget, open: boolean) => (
  <WidgetConfigProvider host={{ kind: 'workspace' }} disabledSteps={[]} initialWidget={initialWidget} initialVariableName={undefined} open={open}>
    <CaptureContext />
  </WidgetConfigProvider>
);
// Rendered once what it reads from the API is read
const renderProvider = async (initialWidget = brokenDownLine) => {
  const rendered = testRender(provider(initialWidget, true), { userContext });
  await act(async () => {});
  return rendered;
};

// The fields the API offers (timeSeriesBreakdownFields) for the types of these tests
const API_FIELDS: Record<string, string[]> = {
  'entities:': ['entity_type'],
  'entities:Report': ['report_types'],
  'entities:Malware': ['malware_types'],
};
const readApiFields = async (perspective: string, types: string[]) => API_FIELDS[`${perspective}:${types.join(',')}`] ?? [];
// Fields read when the test says so, in any order
const readFieldsOnDemand = () => {
  const pending: { perspective: string; types: string[]; read: (keys: string[] | null) => void }[] = [];
  mocks.fetchTimeSeriesBreakdownFields.mockImplementation((perspective: string, types: string[]) => new Promise((resolve) => {
    pending.push({ perspective, types, read: resolve });
  }));
  return pending;
};

const context = () => captured.context as WidgetConfigContext;
const changeWidget = (changes: Partial<WidgetConfigContext['config']['widget']>) => act(async () => {
  context().setConfigWidget({ ...context().config.widget, ...changes });
});
const changeDataset = (filters: unknown) => act(async () => {
  context().setDataSelectionWithIndex({ ...reports, filters } as unknown as WidgetDataSelection, 0);
});
const submittedParameters = () => context().getSubmittedConfig().widget.parameters;

describe('WidgetConfigProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.flags = ['TIME_SERIES_BREAKDOWN'];
    captured.context = undefined;
    mocks.fetchTimeSeriesBreakdownFields.mockReset();
    mocks.fetchTimeSeriesBreakdownFields.mockImplementation(readApiFields);
  });

  it('keeps the breakdown through a line, donut, line round trip, and drops it on submit only from a donut', async () => {
    await renderProvider();
    // A donut cannot be broken down
    await changeWidget({ type: 'donut' });
    expect(context().config.widget.parameters).toEqual({ title: 'Reports', ...breakdown });
    expect(captured.breakdown?.editorState).toEqual('hidden');
    expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });

    await changeWidget({ type: 'line' });
    expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: 'report_types' });
    expect(context().getSubmittedConfig().widget).toBe(context().config.widget);
    // The fields of the dataset are read once
    expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenCalledTimes(1);
    expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenCalledWith('entities', ['Report']);
  });

  it('drops the stored breakdown of a widget with several datasets on submit', async () => {
    await renderProvider({ ...brokenDownLine, dataSelection: [reports, reports] });
    expect(captured.breakdown).toMatchObject({ editorState: 'several-datasets', field: null });
    // Not before: the editor opens on the filters step, which no longer drops it
    act(() => context().setDataSelectionWithIndex(reports, 0));
    expect(context().config.widget.parameters).toEqual({ title: 'Reports', ...breakdown });
    expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });
  });

  it('drops a field the dataset types no longer carry on submit, and keeps it when they carry it again', async () => {
    await renderProvider();
    await changeDataset(ofType('Malware'));
    expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: null });
    expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });
    await changeDataset(ofType('Report'));
    expect(submittedParameters()).toEqual({ title: 'Reports', ...breakdown });
  });

  describe('with the fields of the dataset read from the API', () => {
    it('cannot be submitted with a breakdown until the fields are read, and can be without', async () => {
      const fields = readFieldsOnDemand();
      await renderProvider();
      act(() => context().setStep(3));
      expect(captured.breakdown).toMatchObject({ resolution: 'loading', savedFilterResolution: 'resolved', field: 'report_types', fieldOptions: [] });
      expect(captured.isFormValid).toBe(false);
      await changeWidget({ parameters: { title: 'Reports' } });
      expect(captured.isFormValid).toBe(true);
      await changeWidget({ parameters: { ...brokenDownLine.parameters } });

      await act(async () => fields[0].read(['report_types']));
      expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: 'report_types' });
      expect(captured.isFormValid).toBe(true);
    });

    it('keeps the breakdown when the fields cannot be read, without blaming the saved filter', async () => {
      mocks.fetchTimeSeriesBreakdownFields.mockResolvedValue(null);
      await renderProvider({ ...brokenDownLine, dataSelection: [{ ...reports, filters: ofType('Malware') } as unknown as WidgetDataSelection] });
      act(() => context().setStep(3));
      expect(captured.breakdown).toMatchObject({ resolution: 'failed', savedFilterResolution: 'resolved', field: 'report_types', fieldOptions: [] });
      expect(captured.isFormValid).toBe(true);
      expect(submittedParameters()).toEqual({ title: 'Reports', ...breakdown });
    });

    it('ignores the fields read for a dataset the widget no longer reads, and keeps them for it', async () => {
      const fields = readFieldsOnDemand();
      await renderProvider();
      await changeDataset(ofType('Malware'));
      expect(fields.map(({ types }) => types)).toEqual([['Report'], ['Malware']]);

      await act(async () => fields[1].read(['malware_types']));
      expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: null });
      expect(captured.breakdown?.fieldOptions.map(({ key }) => key)).toEqual(['malware_types']);
      // The fields of the reports, read last, are not the ones of the dataset
      await act(async () => fields[0].read(['report_types']));
      expect(captured.breakdown?.fieldOptions.map(({ key }) => key)).toEqual(['malware_types']);
      expect(captured.breakdown?.field).toBeNull();

      // ...but they are when it reads the reports again, without reading them again
      await changeDataset(ofType('Report'));
      expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: 'report_types' });
      expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenCalledTimes(2);
    });

    it('reads the fields of the same types once, whatever their order', async () => {
      const ofTypes = (types: string[]) => ({ mode: 'and', filters: [{ key: 'entity_type', values: types, operator: 'eq', mode: 'or' }], filterGroups: [] });
      await renderProvider();
      await changeDataset(ofTypes(['Report', 'Malware']));
      await changeDataset(ofTypes(['Malware', 'Report']));
      expect(mocks.fetchTimeSeriesBreakdownFields.mock.calls).toEqual([['entities', ['Report']], ['entities', ['Malware', 'Report']]]);
    });

    it('does not read the fields again within an opening when they cannot be read', async () => {
      mocks.fetchTimeSeriesBreakdownFields.mockResolvedValue(null);
      await renderProvider();
      await changeDataset(ofType('Malware'));
      await changeDataset(ofType('Report'));
      expect(captured.breakdown).toMatchObject({ resolution: 'failed', field: 'report_types' });
      expect(mocks.fetchTimeSeriesBreakdownFields.mock.calls).toEqual([['entities', ['Report']], ['entities', ['Malware']]]);
    });

    it('reads the fields again each time the editor opens, and ignores the ones read for a previous opening', async () => {
      const fields = readFieldsOnDemand();
      const { rerender } = await renderProvider();
      expect(fields).toHaveLength(1);
      rerender(provider(brokenDownLine, false));
      rerender(provider(brokenDownLine, true));
      await act(async () => {});
      expect(fields).toHaveLength(2);

      // Read for the previous opening: the fields may have changed since
      await act(async () => fields[0].read(['report_types']));
      expect(captured.breakdown).toMatchObject({ resolution: 'loading', field: 'report_types' });
      await act(async () => fields[1].read(['createdBy']));
      expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: null });

      // Read once per opening
      await changeWidget({ type: 'donut' });
      await changeWidget({ type: 'line' });
      expect(fields).toHaveLength(2);
      rerender(provider(brokenDownLine, false));
      rerender(provider(brokenDownLine, true));
      await act(async () => {});
      expect(fields).toHaveLength(3);
    });
  });

  describe('with a saved filter', () => {
    const savedFilter = { perspective: 'entities', filters_id: 'saved-filter', filters: undefined } as unknown as WidgetDataSelection;
    const savedFilterLine = { ...brokenDownLine, dataSelection: [savedFilter] };
    const readOnDemand = () => {
      const pending: { read: (filters: unknown) => void } = { read: () => {} };
      mocks.fetchSavedFilterContent.mockReturnValue(new Promise((resolve) => {
        pending.read = resolve;
      }));
      return pending;
    };

    it('cannot be submitted with a breakdown until the saved filter is read, once for every step', async () => {
      const savedFilterContent = readOnDemand();
      await renderProvider(savedFilterLine);
      act(() => context().setStep(3));
      expect(captured.breakdown).toMatchObject({ resolution: 'loading', savedFilterResolution: 'loading', field: 'report_types' });
      expect(captured.isFormValid).toBe(false);
      // Not read again by a widget that no longer needs it, then needs it again
      await changeWidget({ type: 'donut' });
      await changeWidget({ type: 'line' });
      expect(captured.isFormValid).toBe(false);
      // Its fields are asked once it is read
      expect(mocks.fetchTimeSeriesBreakdownFields).not.toHaveBeenCalled();

      await act(async () => savedFilterContent.read(ofType('Malware')));
      await act(async () => {});
      expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenCalledWith('entities', ['Malware']);
      expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: null });
      expect(captured.isFormValid).toBe(true);
      expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });
      // Read once, whatever the widget becomes meanwhile
      await changeWidget({ type: 'donut' });
      await changeWidget({ type: 'line' });
      expect(mocks.fetchSavedFilterContent).toHaveBeenCalledTimes(1);
      expect(mocks.fetchSavedFilterContent).toHaveBeenCalledWith('saved-filter');
      expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenCalledTimes(1);
    });

    it('can be submitted without breakdown while the saved filter is read', async () => {
      readOnDemand();
      await renderProvider({ ...savedFilterLine, parameters: { title: 'Reports' } });
      act(() => context().setStep(3));
      expect(captured.breakdown?.resolution).toEqual('loading');
      expect(captured.isFormValid).toBe(true);
    });

    it('keeps the breakdown of a saved filter that cannot be read, and says so', async () => {
      mocks.fetchSavedFilterContent.mockResolvedValue(null);
      await renderProvider(savedFilterLine);
      act(() => context().setStep(3));
      await act(async () => {});
      expect(captured.breakdown).toMatchObject({ resolution: 'failed', savedFilterResolution: 'failed', field: 'report_types' });
      // The fields of any type
      expect(mocks.fetchTimeSeriesBreakdownFields).toHaveBeenCalledWith('entities', []);
      expect(captured.isFormValid).toBe(true);
      expect(submittedParameters()).toEqual({ title: 'Reports', ...breakdown });
    });
  });

  it('keeps the stored breakdown as it is without the TIME_SERIES_BREAKDOWN feature flag', async () => {
    mocks.flags = [];
    await renderProvider({ ...brokenDownLine, dataSelection: [{ ...reports, filters_id: 'saved-filter' } as unknown as WidgetDataSelection] });
    await changeWidget({ type: 'donut' });
    expect(context().config.widget.type).toBe('donut');
    expect(submittedParameters()).toEqual({ title: 'Reports', ...breakdown });
    expect(captured.breakdown?.editorState).toEqual('hidden');
    expect(mocks.fetchSavedFilterContent).not.toHaveBeenCalled();
    expect(mocks.fetchTimeSeriesBreakdownFields).not.toHaveBeenCalled();
  });
});
