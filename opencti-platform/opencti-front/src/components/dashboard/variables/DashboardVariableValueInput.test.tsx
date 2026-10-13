import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, screen } from '@testing-library/react';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import testRender from '../../../utils/tests/test-render';

const mockSearchEntities = vi.fn();
const mockUseSearchEntities = vi.fn();
let mockEntities: Record<string, FilterOptionValue[]> = {};

vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: (args: unknown) => {
    mockUseSearchEntities(args);
    return [mockEntities, mockSearchEntities];
  },
}));

import DashboardVariableValueInput, { type DashboardVariableShape } from './DashboardVariableValueInput';

const none = { mode: 'none' } as const;

const renderInput = (variable: DashboardVariableShape, value = '') => {
  const onChange = vi.fn();
  const rendered = testRender(<DashboardVariableValueInput variable={variable} value={value} onChange={onChange} />);
  return { ...rendered, onChange };
};

const optionNames = () => screen.getAllByRole('option').map((option) => option.textContent);

describe('DashboardVariableValueInput', () => {
  beforeEach(() => {
    mockEntities = {};
    mockSearchEntities.mockReset();
    mockUseSearchEntities.mockReset();
  });

  describe('boolean', () => {
    it('emits true when true is picked', async () => {
      const { user, onChange } = renderInput({ type: 'boolean', restriction: none }, 'false');
      await user.click(screen.getByRole('combobox'));
      expect(optionNames()).toEqual(['True', 'False']);
      await user.click(screen.getByRole('option', { name: 'True' }));
      expect(onChange).toHaveBeenCalledWith('true');
    });
  });

  describe('numeric and text', () => {
    it('emits a number typed in a number field and never an empty value', async () => {
      const { user, onChange } = renderInput({ type: 'numeric', restriction: none }, '7');
      const input = screen.getByRole('spinbutton');
      await user.clear(input);
      await user.type(input, '42');
      expect(input).toHaveValue(42);
      expect(onChange).toHaveBeenLastCalledWith('42');
      expect(onChange).not.toHaveBeenCalledWith('');
    });

    it('emits the typed text', async () => {
      const { user, onChange } = renderInput({ type: 'text', restriction: none });
      await user.click(screen.getByRole('textbox'));
      await user.paste('Energy');
      expect(onChange).toHaveBeenCalledWith('Energy');
    });

    it('refuses a value referencing a variable', async () => {
      const { user, onChange } = renderInput({ type: 'text', restriction: none });
      await user.click(screen.getByRole('textbox'));
      await user.paste('$var:5f1c3b4e-8f8a-4c4b-9a59-2a1f2c3d4e5f');
      expect(onChange).not.toHaveBeenCalled();
      expect(screen.getByText('A value cannot reference another variable')).toBeInTheDocument();
    });

    it('shows the value received after a reset', () => {
      const onChange = vi.fn();
      const { rerender } = testRender(<DashboardVariableValueInput variable={{ type: 'text', restriction: none }} value="Energy" onChange={onChange} />);
      rerender(<DashboardVariableValueInput variable={{ type: 'text', restriction: none }} value="Finance" onChange={onChange} />);
      expect(screen.getByRole('textbox')).toHaveValue('Finance');
    });
  });

  describe('selection restriction', () => {
    it('only offers the values of the selection', async () => {
      const variable: DashboardVariableShape = { type: 'text', restriction: { mode: 'selection', values: ['alpha', 'beta'] } };
      const { user, onChange } = renderInput(variable, 'alpha');
      await user.click(screen.getByRole('combobox'));
      expect(optionNames()).toEqual(['alpha', 'beta']);
      await user.click(screen.getByRole('option', { name: 'beta' }));
      expect(onChange).toHaveBeenCalledWith('beta');
      expect(mockUseSearchEntities).not.toHaveBeenCalled();
    });

    it('labels the selected entities and never shows a raw id', async () => {
      const variable: DashboardVariableShape = { type: 'label', restriction: { mode: 'selection', values: ['label-1', 'label-2'] } };
      const { user, relayEnv } = renderInput(variable);
      act(() => {
        relayEnv.mock.resolveMostRecentOperation({
          data: { filtersRepresentatives: [{ representativeId: 'label-1', value: 'malicious', entity_type: 'Label', color: null }] },
        });
      });
      await user.click(screen.getByRole('combobox'));
      expect(optionNames()).toEqual(['malicious', 'Restricted']);
    });
  });

  describe('entity pool', () => {
    it('searches labels and emits the picked label id', async () => {
      mockEntities = {
        objectLabel: [
          { label: 'No label', value: null, type: 'Label' },
          { label: 'malicious', value: 'label-1', type: 'Label' },
        ],
      };
      const { user, onChange } = renderInput({ type: 'label', restriction: none });
      await user.click(screen.getByRole('combobox'));
      expect(mockSearchEntities).toHaveBeenCalledWith('objectLabel', expect.anything(), expect.anything(), expect.anything());
      expect(optionNames()).toEqual(['malicious']);
      await user.click(screen.getByRole('option', { name: 'malicious' }));
      expect(onChange).toHaveBeenCalledWith('label-1');
    });

    it('scopes an entity search to the variable entity types', () => {
      renderInput({ type: 'entity', entityTypes: ['Sector'], restriction: none });
      expect(mockUseSearchEntities).toHaveBeenCalledWith(expect.objectContaining({ searchScope: { id: ['Sector'] } }));
    });

    it('falls back to the free search of its type for a filters restriction', () => {
      const filters = { mode: 'and' as const, filters: [], filterGroups: [] };
      renderInput({ type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'filters', filters } });
      expect(mockUseSearchEntities).toHaveBeenCalledWith(expect.objectContaining({ searchScope: { id: ['Sector'] } }));
    });

    it('does not offer the dynamic @me user', async () => {
      mockEntities = {
        members_user: [
          { label: '@me', value: '@me', type: 'User' },
          { label: 'Alice', value: 'user-1', type: 'User' },
        ],
      };
      const { user } = renderInput({ type: 'user', restriction: none });
      await user.click(screen.getByRole('combobox'));
      expect(optionNames()).toEqual(['Alice']);
    });

    it('only offers the phases of the variable kill chain', async () => {
      mockEntities = {
        killChainPhases: [
          { label: '[mitre-attack] execution', value: 'phase-1', type: 'Kill-Chain-Phase' },
          { label: '[lockheed-martin] delivery', value: 'phase-2', type: 'Kill-Chain-Phase' },
        ],
      };
      const { user } = renderInput({ type: 'killChainPhase', killChainName: 'mitre-attack', restriction: none });
      await user.click(screen.getByRole('combobox'));
      expect(optionNames()).toEqual(['[mitre-attack] execution']);
    });

    it('shows the label of the current value', () => {
      const { relayEnv } = renderInput({ type: 'label', restriction: none }, 'label-1');
      act(() => {
        relayEnv.mock.resolveMostRecentOperation({
          data: { filtersRepresentatives: [{ representativeId: 'label-1', value: 'malicious', entity_type: 'Label', color: null }] },
        });
      });
      expect(screen.getByRole('combobox')).toHaveValue('malicious');
    });
  });

  describe('entity type', () => {
    it('picks a type among the schema types', async () => {
      mockEntities = { entity_type: [{ label: 'Malware', value: 'Malware', type: 'Malware' }] };
      const { user, onChange } = renderInput({ type: 'entityType', restriction: none });
      await user.click(screen.getByRole('combobox'));
      expect(mockSearchEntities).toHaveBeenCalledWith('entity_type', expect.anything(), expect.anything(), expect.anything());
      await user.click(screen.getByRole('option', { name: 'Malware' }));
      expect(onChange).toHaveBeenCalledWith('Malware');
    });
  });

  describe('vocabulary', () => {
    it('offers the entries of the vocabulary category', async () => {
      const { user, relayEnv, onChange } = renderInput({ type: 'vocabulary', vocabularyCategory: 'reliability_ov', restriction: none });
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
      expect(optionNames()).toEqual(['A - Completely reliable', 'B - Usually reliable']);
      await user.click(screen.getByRole('option', { name: 'B - Usually reliable' }));
      expect(onChange).toHaveBeenCalledWith('B - Usually reliable');
    });
  });

  describe('date', () => {
    it('emits the typed date as an ISO string once validated', async () => {
      // Local noon: the picker keeps the time of day, and the day stays the same in any time zone.
      const { user, onChange } = renderInput({ type: 'date', restriction: none }, new Date(2024, 0, 15, 12).toISOString());
      const input = screen.getByRole('textbox');
      expect(input).toHaveValue('01/15/2024');
      await user.click(input);
      await user.keyboard('02202024');
      expect(onChange).not.toHaveBeenCalled();
      await user.keyboard('{Enter}');
      expect(onChange).toHaveBeenCalledWith(new Date(2024, 1, 20, 12).toISOString());
    });
  });
});
