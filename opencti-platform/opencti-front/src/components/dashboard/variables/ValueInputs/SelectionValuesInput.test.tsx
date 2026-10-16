import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import testRender from '../../../../utils/tests/test-render';

const mockSearchEntities = vi.fn();
let mockEntities: Record<string, FilterOptionValue[]> = {};

vi.mock('../../../../utils/filters/useSearchEntities', () => ({
  default: () => [mockEntities, mockSearchEntities],
}));

import SelectionValuesInput from './SelectionValuesInput';
import type { DashboardVariableShape } from '../DashboardVariableValueInput';

const none = { mode: 'none' } as const;
const label: DashboardVariableShape = { type: 'label', restriction: none };

const renderInput = (variable: DashboardVariableShape, values: string[], error?: string) => {
  const onChange = vi.fn();
  const rendered = testRender(<SelectionValuesInput variable={variable} values={values} onChange={onChange} label="Values" error={error} />);
  return { ...rendered, onChange };
};

const resolveLabels = (relayEnv: ReturnType<typeof testRender>['relayEnv'], names: Record<string, string>) => act(() => {
  relayEnv.mock.resolveMostRecentOperation({
    data: {
      filtersRepresentatives: Object.entries(names).map(([representativeId, value]) => ({ representativeId, value, entity_type: 'Label', color: null })),
    },
  });
});

const chipRow = () => screen.getByRole('list', { name: 'Values' });

describe('SelectionValuesInput', () => {
  beforeEach(() => {
    mockEntities = {
      objectLabel: [
        { label: 'malicious', value: 'label-1', type: 'Label' },
        { label: 'benign', value: 'label-2', type: 'Label' },
      ],
    };
    mockSearchEntities.mockReset();
  });

  it('adds a picked value to the selection', async () => {
    const { user, onChange, relayEnv } = renderInput(label, ['label-1']);
    resolveLabels(relayEnv, { 'label-1': 'malicious' });
    await user.click(screen.getByRole('combobox'));
    expect(mockSearchEntities).toHaveBeenCalledWith('objectLabel', expect.anything(), expect.anything(), expect.anything());
    await user.click(screen.getByRole('option', { name: 'benign' }));
    expect(onChange).toHaveBeenLastCalledWith(['label-1', 'label-2']);
  });

  it('removes a value when its option is picked again', async () => {
    const { user, onChange, relayEnv } = renderInput(label, ['label-1', 'label-2']);
    resolveLabels(relayEnv, { 'label-1': 'malicious', 'label-2': 'benign' });
    await user.click(screen.getByRole('combobox'));
    await user.click(screen.getByRole('option', { name: 'malicious' }));
    expect(onChange).toHaveBeenLastCalledWith(['label-2']);
  });

  it('shows each value as a chip, by its label', () => {
    const { relayEnv } = renderInput(label, ['label-1', 'label-2']);
    resolveLabels(relayEnv, { 'label-1': 'malicious', 'label-2': 'benign' });
    expect(within(chipRow()).getByText('malicious')).toBeInTheDocument();
    expect(within(chipRow()).getByText('benign')).toBeInTheDocument();
  });

  it('keeps an unresolved value visible and removable', async () => {
    mockEntities = {};
    const { user, onChange, relayEnv } = renderInput(label, ['label-1', 'deleted-id']);
    resolveLabels(relayEnv, { 'label-1': 'malicious' });
    expect(within(chipRow()).getByText('Restricted')).toBeInTheDocument();
    await user.click(screen.getByRole('combobox'));
    await user.keyboard('{Backspace}');
    expect(onChange).toHaveBeenLastCalledWith(['label-1']);
  });

  it('keeps one chip per value while the labels resolve, and after', () => {
    mockEntities = {};
    const { relayEnv } = renderInput(label, ['label-1', 'label-2', 'label-3']);
    // Same label for every chip while resolving: the library keys its chips by label, each must stay distinct.
    expect(within(chipRow()).getAllByRole('listitem')).toHaveLength(3);
    resolveLabels(relayEnv, { 'label-1': 'malicious', 'label-2': 'benign', 'label-3': 'benign' });
    const chips = within(chipRow()).getAllByRole('listitem');
    expect(chips).toHaveLength(3);
    expect(chips.map((chip) => chip.textContent)).toEqual(['malicious', 'benign', 'benign (2)']);
  });

  it('keeps the known labels while the labels of a new selection resolve', () => {
    mockEntities = {};
    const onChange = vi.fn();
    const { relayEnv, rerender } = testRender(<SelectionValuesInput variable={label} values={['label-1']} onChange={onChange} label="Values" />);
    resolveLabels(relayEnv, { 'label-1': 'malicious' });
    rerender(<SelectionValuesInput variable={label} values={['label-1', 'label-2']} onChange={onChange} label="Values" />);
    expect(within(chipRow()).getAllByRole('listitem').map((chip) => chip.textContent)).toEqual(['malicious', 'Loading']);
  });

  it('offers the names of the vocabulary category for a vocabulary variable', async () => {
    const variable: DashboardVariableShape = { type: 'vocabulary', vocabularyCategory: 'reliability_ov', restriction: none };
    const { user, relayEnv, onChange } = renderInput(variable, []);
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables.category).toBe('reliability_ov');
    act(() => {
      relayEnv.mock.resolve(operation, {
        data: {
          vocabularies: {
            edges: ['A - Completely reliable', 'B - Usually reliable'].map((name) => ({
              node: { id: name, name, category: { key: 'reliability_ov', fields: [] } },
            })),
          },
        },
      });
    });
    await user.click(screen.getByRole('combobox'));
    expect(screen.getAllByRole('option').map((option) => option.textContent)).toEqual(['A - Completely reliable', 'B - Usually reliable']);
    expect(mockSearchEntities).not.toHaveBeenCalled();
    await user.click(screen.getByRole('option', { name: 'B - Usually reliable' }));
    expect(onChange).toHaveBeenLastCalledWith(['B - Usually reliable']);
  });

  it('shows the error under the field', () => {
    renderInput(label, [], 'Select at least one value');
    expect(screen.getByText('Select at least one value')).toBeInTheDocument();
  });
});
