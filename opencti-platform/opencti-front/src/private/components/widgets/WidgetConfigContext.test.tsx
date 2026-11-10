import React from 'react';
import { act } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Widget, WidgetDataSelection } from '../../../utils/widget/widget';

const mocks = vi.hoisted(() => ({
  fetchSavedFilterContent: vi.fn(),
}));
vi.mock('../../../components/dashboard/dashboardVizUtils', () => ({
  fetchSavedFilterContent: mocks.fetchSavedFilterContent,
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

const renderProvider = (initialWidget = brokenDownLine) => testRender(
  <WidgetConfigProvider host={{ kind: 'workspace' }} disabledSteps={[]} initialWidget={initialWidget} initialVariableName={undefined} open>
    <CaptureContext />
  </WidgetConfigProvider>,
  { userContext },
);

const context = () => captured.context as WidgetConfigContext;
const changeWidget = (changes: Partial<WidgetConfigContext['config']['widget']>) => act(() => {
  context().setConfigWidget({ ...context().config.widget, ...changes });
});
const submittedParameters = () => context().getSubmittedConfig().widget.parameters;

describe('WidgetConfigProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    captured.context = undefined;
  });

  it('keeps the breakdown through a line, donut, line round trip, and drops it on submit only from a donut', () => {
    renderProvider();
    // A donut cannot be broken down
    changeWidget({ type: 'donut' });
    expect(context().config.widget.parameters).toEqual({ title: 'Reports', ...breakdown });
    expect(captured.breakdown?.editorState).toEqual('hidden');
    expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });

    changeWidget({ type: 'line' });
    expect(captured.breakdown?.field).toEqual('report_types');
    expect(context().getSubmittedConfig().widget).toBe(context().config.widget);
  });

  it('drops the stored breakdown of a widget with several datasets on submit', () => {
    renderProvider({ ...brokenDownLine, dataSelection: [reports, reports] });
    expect(captured.breakdown).toMatchObject({ editorState: 'several-datasets', field: null });
    // Not before: the editor opens on the filters step, which no longer drops it
    act(() => context().setDataSelectionWithIndex(reports, 0));
    expect(context().config.widget.parameters).toEqual({ title: 'Reports', ...breakdown });
    expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });
  });

  it('drops a field the dataset types no longer carry on submit, and keeps it when they carry it again', () => {
    renderProvider();
    act(() => context().setDataSelectionWithIndex({ ...reports, filters: ofType('Malware') } as unknown as WidgetDataSelection, 0));
    expect(captured.breakdown?.field).toBeNull();
    expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });
    act(() => context().setDataSelectionWithIndex(reports, 0));
    expect(submittedParameters()).toEqual({ title: 'Reports', ...breakdown });
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
      renderProvider(savedFilterLine);
      act(() => context().setStep(3));
      expect(captured.breakdown).toMatchObject({ resolution: 'loading', field: 'report_types' });
      expect(captured.isFormValid).toBe(false);
      // Not read again by a widget that no longer needs it, then needs it again
      changeWidget({ type: 'donut' });
      changeWidget({ type: 'line' });
      expect(captured.isFormValid).toBe(false);

      await act(async () => savedFilterContent.read(ofType('Malware')));
      expect(captured.breakdown).toMatchObject({ resolution: 'resolved', field: null });
      expect(captured.isFormValid).toBe(true);
      expect(submittedParameters()).toEqual({ title: 'Reports', ...NO_BREAKDOWN });
      // Read once, whatever the widget becomes meanwhile
      changeWidget({ type: 'donut' });
      changeWidget({ type: 'line' });
      expect(mocks.fetchSavedFilterContent).toHaveBeenCalledTimes(1);
      expect(mocks.fetchSavedFilterContent).toHaveBeenCalledWith('saved-filter');
    });

    it('can be submitted without breakdown while the saved filter is read', () => {
      readOnDemand();
      renderProvider({ ...savedFilterLine, parameters: { title: 'Reports' } });
      act(() => context().setStep(3));
      expect(captured.breakdown?.resolution).toEqual('loading');
      expect(captured.isFormValid).toBe(true);
    });

    it('keeps the breakdown of a saved filter that cannot be read', async () => {
      mocks.fetchSavedFilterContent.mockResolvedValue(null);
      renderProvider(savedFilterLine);
      act(() => context().setStep(3));
      await act(async () => {});
      expect(captured.breakdown).toMatchObject({ resolution: 'failed', field: 'report_types' });
      expect(captured.isFormValid).toBe(true);
      expect(submittedParameters()).toEqual({ title: 'Reports', ...breakdown });
    });
  });
});
