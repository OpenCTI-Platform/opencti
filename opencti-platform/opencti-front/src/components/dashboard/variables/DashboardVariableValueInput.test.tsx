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

const renderInput = (variable: DashboardVariableShape, value = '', commitOn?: 'change' | 'blur') => {
  const onChange = vi.fn();
  const rendered = testRender(<DashboardVariableValueInput variable={variable} value={value} onChange={onChange} commitOn={commitOn} />);
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

    it('emits an empty value when cleared, so a form can drop its default', async () => {
      const { user, onChange } = renderInput({ type: 'boolean', restriction: none }, 'true');
      await user.click(screen.getByRole('button', { name: 'Clear' }));
      expect(onChange).toHaveBeenCalledTimes(1);
      expect(onChange).toHaveBeenCalledWith('');
    });

    it('starts with no choice and emits nothing on its own when the value is empty', () => {
      const { onChange } = renderInput({ type: 'boolean', restriction: none }, '');
      expect(screen.getByRole('combobox')).not.toHaveTextContent(/True|False/);
      expect(onChange).not.toHaveBeenCalled();
    });

    it('offers no clear control, and emits nothing empty, when committed on blur', async () => {
      const { onChange } = renderInput({ type: 'boolean', restriction: none }, 'true', 'blur');
      expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
      expect(onChange).not.toHaveBeenCalled();
    });
  });

  describe('numeric and text', () => {
    it('emits a number typed in a number field, and an empty value once it is emptied', async () => {
      const { user, onChange } = renderInput({ type: 'numeric', restriction: none }, '7');
      const input = screen.getByRole('spinbutton');
      await user.clear(input);
      expect(onChange).toHaveBeenLastCalledWith('');
      await user.type(input, '42');
      expect(input).toHaveValue(42);
      expect(onChange).toHaveBeenLastCalledWith('42');
    });

    it('emits an empty value when the text is emptied, or only blank', async () => {
      const { user, onChange } = renderInput({ type: 'text', restriction: none }, 'Energy');
      const input = screen.getByRole('textbox');
      await user.clear(input);
      expect(onChange).toHaveBeenLastCalledWith('');
      await user.type(input, '   ');
      expect(onChange).toHaveBeenLastCalledWith('');
      expect(input).toHaveValue('   ');
    });

    it('keeps refusing a value referencing a variable after emptying the field', async () => {
      const { user, onChange } = renderInput({ type: 'text', restriction: none }, 'Energy');
      const input = screen.getByRole('textbox');
      await user.clear(input);
      onChange.mockClear();
      await user.click(input);
      await user.paste('$var:5f1c3b4e-8f8a-4c4b-9a59-2a1f2c3d4e5f');
      expect(onChange).not.toHaveBeenCalled();
      expect(screen.getByText('A value cannot reference another variable')).toBeInTheDocument();
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

    describe('committed on blur', () => {
      it('emits the final text once, on blur, and nothing while typing', async () => {
        const { user, onChange } = renderInput({ type: 'text', restriction: none }, '', 'blur');
        await user.type(screen.getByRole('textbox'), 'Financial services');
        expect(onChange).not.toHaveBeenCalled();
        await user.tab();
        expect(onChange).toHaveBeenCalledTimes(1);
        expect(onChange).toHaveBeenCalledWith('Financial services');
      });

      it('emits the final number once, on blur', async () => {
        const { user, onChange } = renderInput({ type: 'numeric', restriction: none }, '7', 'blur');
        const input = screen.getByRole('spinbutton');
        await user.clear(input);
        await user.type(input, '42');
        expect(onChange).not.toHaveBeenCalled();
        await user.tab();
        expect(onChange).toHaveBeenCalledTimes(1);
        expect(onChange).toHaveBeenCalledWith('42');
      });

      it('emits on Enter', async () => {
        const { user, onChange } = renderInput({ type: 'text', restriction: none }, '', 'blur');
        await user.type(screen.getByRole('textbox'), 'Energy{Enter}');
        expect(onChange).toHaveBeenCalledTimes(1);
        expect(onChange).toHaveBeenCalledWith('Energy');
      });

      it('emits nothing on blur when the text did not change', async () => {
        const { user, onChange } = renderInput({ type: 'text', restriction: none }, 'Energy', 'blur');
        await user.click(screen.getByRole('textbox'));
        await user.tab();
        expect(onChange).not.toHaveBeenCalled();
      });

      it('emits nothing for an emptied number field', async () => {
        const { user, onChange } = renderInput({ type: 'numeric', restriction: none }, '7', 'blur');
        await user.clear(screen.getByRole('spinbutton'));
        await user.tab();
        expect(onChange).not.toHaveBeenCalled();
      });

      it('emits nothing for an emptied field, nor for a value referencing a variable', async () => {
        const { user, onChange } = renderInput({ type: 'text', restriction: none }, 'Energy', 'blur');
        const input = screen.getByRole('textbox');
        await user.clear(input);
        await user.tab();
        expect(onChange).not.toHaveBeenCalled();
        await user.click(input);
        await user.paste('$var:5f1c3b4e-8f8a-4c4b-9a59-2a1f2c3d4e5f');
        await user.tab();
        expect(onChange).not.toHaveBeenCalled();
      });

      it('shows the value received after a reset, dropping the typed text', async () => {
        const onChange = vi.fn();
        const variable = { type: 'text', restriction: none } as const;
        const { user, rerender } = testRender(<DashboardVariableValueInput variable={variable} value="Energy" onChange={onChange} commitOn="blur" />);
        await user.type(screen.getByRole('textbox'), ' and more');
        rerender(<DashboardVariableValueInput variable={variable} value="Finance" onChange={onChange} commitOn="blur" />);
        expect(screen.getByRole('textbox')).toHaveValue('Finance');
      });
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

    it('labels the selected kill chain phase `[kill chain] phase`', async () => {
      const variable: DashboardVariableShape = {
        type: 'killChainPhase',
        killChainName: 'mitre-attack',
        restriction: { mode: 'selection', values: ['phase-1', 'phase-2'] },
      };
      const { user, relayEnv } = renderInput(variable, 'phase-1');
      act(() => {
        relayEnv.mock.resolveMostRecentOperation({
          data: {
            filtersRepresentatives: [
              { representativeId: 'phase-1', value: 'persistence', entity_type: 'Kill-Chain-Phase', color: null },
              { representativeId: 'phase-2', value: 'execution', entity_type: 'Kill-Chain-Phase', color: null },
            ],
          },
        });
      });
      await user.click(screen.getByRole('combobox'));
      expect(optionNames()).toEqual(['[mitre-attack] persistence', '[mitre-attack] execution']);
    });

    it('emits an empty value when cleared, and nothing empty when committed on blur', async () => {
      const variable: DashboardVariableShape = { type: 'text', restriction: { mode: 'selection', values: ['alpha', 'beta'] } };
      const changing = renderInput(variable, 'alpha');
      await changing.user.click(screen.getByRole('button', { name: 'Clear' }));
      expect(changing.onChange).toHaveBeenCalledWith('');
      changing.unmount();
      renderInput(variable, 'alpha', 'blur');
      expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
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

  describe('entity restricted by filters', () => {
    const rule = {
      mode: 'and',
      filters: [{ key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };

    it('searches within the rule, never through the free search of its type', async () => {
      const variable: DashboardVariableShape = { type: 'entity', entityTypes: ['Organization'], restriction: { mode: 'filters', filters: rule } };
      const { user, onChange, relayEnv } = renderInput(variable);
      await user.click(screen.getByRole('combobox'));
      expect(mockSearchEntities).not.toHaveBeenCalled();
      const operation = relayEnv.mock.getMostRecentOperation();
      expect(operation.request.variables).toEqual(expect.objectContaining({ search: '', types: ['Organization'] }));
      expect(operation.request.variables.filters.filters[0]).toEqual(expect.objectContaining({ key: ['objectLabel'], values: ['label-1'] }));
      act(() => {
        relayEnv.mock.resolve(operation, {
          data: { stixCoreObjects: { edges: [{ node: { id: 'org-1', entity_type: 'Organization', representative: { main: 'Acme Corp' } } }] } },
        });
      });
      await user.click(await screen.findByRole('option', { name: 'Acme Corp' }));
      expect(onChange).toHaveBeenCalledWith('org-1');
    });

    it('goes back to every entity of the rule once a value is picked', async () => {
      const variable: DashboardVariableShape = { type: 'entity', entityTypes: ['Organization'], restriction: { mode: 'filters', filters: rule } };
      const { user, relayEnv } = renderInput(variable);
      await user.click(screen.getByRole('combobox'));
      await user.type(screen.getByRole('combobox'), 'ac');
      act(() => {
        relayEnv.mock.resolveMostRecentOperation({
          data: { stixCoreObjects: { edges: [{ node: { id: 'org-1', entity_type: 'Organization', representative: { main: 'Acme Corp' } } }] } },
        });
      });
      await user.click(await screen.findByRole('option', { name: 'Acme Corp' }));
      expect(relayEnv.mock.getMostRecentOperation().request.variables.search).toBe('');
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

    it('emits an empty value when the selected entity is cleared', async () => {
      mockEntities = { objectLabel: [{ label: 'malicious', value: 'label-1', type: 'Label' }] };
      const { user, onChange, relayEnv } = renderInput({ type: 'label', restriction: none }, 'label-1');
      act(() => {
        relayEnv.mock.resolveMostRecentOperation({
          data: { filtersRepresentatives: [{ representativeId: 'label-1', value: 'malicious', entity_type: 'Label', color: null }] },
        });
      });
      await user.click(screen.getByRole('button', { name: 'Clear' }));
      expect(onChange).toHaveBeenCalledTimes(1);
      expect(onChange).toHaveBeenCalledWith('');
    });

    it('emits nothing empty, and offers no clear control, when committed on blur', async () => {
      const { user, onChange, relayEnv } = renderInput({ type: 'label', restriction: none }, 'label-1', 'blur');
      act(() => {
        relayEnv.mock.resolveMostRecentOperation({
          data: { filtersRepresentatives: [{ representativeId: 'label-1', value: 'malicious', entity_type: 'Label', color: null }] },
        });
      });
      expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
      await user.clear(screen.getByRole('combobox'));
      await user.tab();
      expect(onChange).not.toHaveBeenCalled();
    });

    it('scopes an entity search to the variable entity types', () => {
      renderInput({ type: 'entity', entityTypes: ['Sector'], restriction: none });
      expect(mockUseSearchEntities).toHaveBeenCalledWith(expect.objectContaining({ searchScope: { id: ['Sector'] } }));
    });

    it('searches entities as soon as the field is focused', async () => {
      const { user } = renderInput({ type: 'entity', entityTypes: ['Sector'], restriction: none });
      await user.click(screen.getByRole('combobox'));
      expect(mockSearchEntities).toHaveBeenCalledWith('id', expect.anything(), expect.anything(), expect.anything());
    });

    it('never searches, nor offers, unrelated entities for a variable of External-Reference only', async () => {
      // The shared search drops External-Reference from the scope and, left empty, reads it as "any entity".
      mockEntities = { id: [{ label: 'APT28', value: 'malware-1', type: 'Malware', parentTypes: ['Stix-Domain-Object'] }] };
      const { user } = renderInput({ type: 'entity', entityTypes: ['External-Reference'], restriction: none });
      await user.click(screen.getByRole('combobox'));
      await user.type(screen.getByRole('combobox'), 'apt');
      expect(mockSearchEntities).not.toHaveBeenCalled();
      expect(screen.queryAllByRole('option')).toHaveLength(0);
      expect(screen.getByText('No available options')).toBeInTheDocument();
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

    describe('kill chain phase', () => {
      // The platform of the review: many phases of one kill chain, sorted before the few phases of another one.
      const platformPhases = [
        ...Array.from({ length: 600 }, (_, index) => ({ id: `bulk-${index}`, kill_chain_name: 'bulk-chain', phase_name: `phase ${index}` })),
        { id: 'rare-1', kill_chain_name: 'rare-chain', phase_name: 'reconnaissance' },
        { id: 'rare-2', kill_chain_name: 'rare-chain', phase_name: 'delivery' },
      ];
      // Answers the kill chain phases query like the back does: the kill chain filter, then the first `first` phases.
      const answerPhasesQuery = (variables: Record<string, unknown>) => {
        const filters = variables.filters as { filters: { key: string[]; values: string[] }[] } | null;
        const killChainName = filters?.filters.find((filter) => filter.key.includes('kill_chain_name'))?.values[0];
        const matching = platformPhases.filter((phase) => killChainName === undefined || phase.kill_chain_name === killChainName);
        return { data: { killChainPhases: { edges: matching.slice(0, (variables.first as number | null) ?? 500).map((node) => ({ node })) } } };
      };
      const killChainFilters = {
        mode: 'and',
        filters: [{ key: ['kill_chain_name'], values: ['rare-chain'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      };

      it('searches the phases of the variable kill chain on the server, not through the shared search', async () => {
        const { user, relayEnv } = renderInput({ type: 'killChainPhase', killChainName: 'rare-chain', restriction: none });
        await user.click(screen.getByRole('combobox'));
        const operation = relayEnv.mock.getMostRecentOperation();
        expect(operation.request.node.operation.name).toBe('useKillChainPhaseSearchQuery');
        expect(operation.request.variables).toEqual({ search: '', first: 100, filters: killChainFilters });
        expect(mockSearchEntities).not.toHaveBeenCalled();
      });

      it('lists the phases of a kill chain that the first unscoped page of phases would miss', async () => {
        const { user, relayEnv, onChange } = renderInput({ type: 'killChainPhase', killChainName: 'rare-chain', restriction: none });
        await user.click(screen.getByRole('combobox'));
        act(() => {
          relayEnv.mock.resolveMostRecentOperation((operation) => answerPhasesQuery(operation.request.variables));
        });
        expect(optionNames()).toEqual(['[rare-chain] reconnaissance', '[rare-chain] delivery']);
        await user.click(screen.getByRole('option', { name: '[rare-chain] delivery' }));
        expect(onChange).toHaveBeenCalledWith('rare-2');
      });

      it('does not search the label of a picked phase, only a typed text', async () => {
        const { user, relayEnv } = renderInput({ type: 'killChainPhase', killChainName: 'rare-chain', restriction: none });
        await user.click(screen.getByRole('combobox'));
        act(() => {
          relayEnv.mock.resolveMostRecentOperation((operation) => answerPhasesQuery(operation.request.variables));
        });
        // A resolved search is no longer pending: any search listed below was issued after this point.
        const pendingSearches = () => relayEnv.mock.getAllOperations().map((operation) => operation.request.variables.search);
        expect(pendingSearches()).toEqual([]);
        await user.click(screen.getByRole('option', { name: '[rare-chain] delivery' }));
        expect(pendingSearches()).not.toContain('[rare-chain] delivery');
        await user.clear(screen.getByRole('combobox'));
        await user.type(screen.getByRole('combobox'), 'del');
        expect(relayEnv.mock.getMostRecentOperation().request.variables).toEqual({ search: 'del', first: 100, filters: killChainFilters });
      });

      it('searches the typed text among the phases of the kill chain', async () => {
        const { user, relayEnv } = renderInput({ type: 'killChainPhase', killChainName: 'rare-chain', restriction: none });
        await user.click(screen.getByRole('combobox'));
        await user.keyboard('r');
        expect(relayEnv.mock.getMostRecentOperation().request.variables).toEqual({ search: 'r', first: 100, filters: killChainFilters });
      });

      describe('when the phases cannot be listed', () => {
        // Listing the phases needs the knowledge access, which not every user has: the default value is an id, so no
        // free text can replace the list, and the field says why it offers nothing.
        const listingError = 'The kill chain phases cannot be listed with your access rights or right now';
        const rareChain: DashboardVariableShape = { type: 'killChainPhase', killChainName: 'rare-chain', restriction: none };

        it('says so, and offers no phase', async () => {
          const { user, relayEnv } = renderInput(rareChain);
          expect(screen.queryByText(listingError)).not.toBeInTheDocument();
          await user.click(screen.getByRole('combobox'));
          act(() => {
            relayEnv.mock.rejectMostRecentOperation(new Error('forbidden'));
          });
          expect(screen.getByText(listingError)).toBeInTheDocument();
          expect(screen.queryAllByRole('option')).toHaveLength(0);
        });

        it('stops saying so once a search succeeds', async () => {
          const { user, relayEnv } = renderInput(rareChain);
          await user.click(screen.getByRole('combobox'));
          act(() => {
            relayEnv.mock.rejectMostRecentOperation(new Error('unavailable'));
          });
          expect(screen.getByText(listingError)).toBeInTheDocument();
          await user.keyboard('r');
          act(() => {
            relayEnv.mock.resolveMostRecentOperation((operation) => answerPhasesQuery(operation.request.variables));
          });
          expect(screen.queryByText(listingError)).not.toBeInTheDocument();
          expect(optionNames()).toEqual(['[rare-chain] reconnaissance', '[rare-chain] delivery']);
        });

        it('stops saying so for another kill chain', async () => {
          const { user, relayEnv, rerender, onChange } = renderInput(rareChain);
          await user.click(screen.getByRole('combobox'));
          act(() => {
            relayEnv.mock.rejectMostRecentOperation(new Error('forbidden'));
          });
          expect(screen.getByText(listingError)).toBeInTheDocument();
          rerender(<DashboardVariableValueInput variable={{ ...rareChain, killChainName: 'bulk-chain' }} value="" onChange={onChange} />);
          expect(screen.queryByText(listingError)).not.toBeInTheDocument();
          // Nor does it come back with the first kill chain: the failure was forgotten, not hidden.
          rerender(<DashboardVariableValueInput variable={rareChain} value="" onChange={onChange} />);
          expect(screen.queryByText(listingError)).not.toBeInTheDocument();
        });

        it('is never said for another type of variable, even when its own query fails', async () => {
          const { user, relayEnv } = renderInput({ type: 'label', restriction: none }, 'label-1');
          act(() => {
            relayEnv.mock.rejectMostRecentOperation(new Error('forbidden'));
          });
          await user.click(screen.getByRole('combobox'));
          expect(screen.queryByText(listingError)).not.toBeInTheDocument();
        });
      });
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

    it('shows the current kill chain phase as `[kill chain] phase`, the way the options are', () => {
      const { relayEnv } = renderInput({ type: 'killChainPhase', killChainName: 'mitre-attack', restriction: none }, 'phase-1');
      act(() => {
        relayEnv.mock.resolveMostRecentOperation({
          data: { filtersRepresentatives: [{ representativeId: 'phase-1', value: 'persistence', entity_type: 'Kill-Chain-Phase', color: null }] },
        });
      });
      expect(screen.getByRole('combobox')).toHaveValue('[mitre-attack] persistence');
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
    // The library picker emits the start of the picked day, in the local time zone.
    const jan15 = new Date(2024, 0, 15).toISOString();
    const feb20 = new Date(2024, 1, 20).toISOString();
    const dateInput = () => screen.getByRole('textbox', { name: 'Value' });
    const typeDate = async (user: ReturnType<typeof testRender>['user'], text: string) => {
      await user.click(dateInput());
      await user.keyboard(`{Control>}a{/Control}${text}`);
    };

    it('shows the stored date in the format of the platform language', () => {
      renderInput({ type: 'date', restriction: none }, jan15);
      expect(dateInput()).toHaveValue('01/15/2024');
    });

    it('emits the typed date as an ISO string once validated', async () => {
      const { user, onChange } = renderInput({ type: 'date', restriction: none }, jan15);
      await typeDate(user, '02/20/2024');
      expect(onChange).not.toHaveBeenCalled();
      await user.keyboard('{Enter}');
      expect(onChange).toHaveBeenCalledWith(feb20);
    });

    it('emits the typed date on blur', async () => {
      const { user, onChange } = renderInput({ type: 'date', restriction: none }, jan15, 'blur');
      await typeDate(user, '02/20/2024');
      await user.tab();
      expect(onChange).toHaveBeenCalledTimes(1);
      expect(onChange).toHaveBeenCalledWith(feb20);
    });

    it('emits nothing for a date that is incomplete or unchanged', async () => {
      const { user, onChange } = renderInput({ type: 'date', restriction: none }, jan15, 'blur');
      await typeDate(user, '02/2');
      await user.tab();
      expect(onChange).not.toHaveBeenCalled();
      await typeDate(user, '01/15/2024');
      await user.keyboard('{Enter}');
      expect(onChange).not.toHaveBeenCalled();
    });

    it('emits the day picked in the calendar', async () => {
      const { user, onChange } = renderInput({ type: 'date', restriction: none }, jan15, 'blur');
      await user.click(screen.getByRole('button', { name: 'Open calendar' }));
      await user.click(await screen.findByRole('gridcell', { name: /January 20, 2024/ }));
      expect(onChange).toHaveBeenCalledTimes(1);
      expect(onChange).toHaveBeenCalledWith(new Date(2024, 0, 20).toISOString());
    });

    it('starts empty and emits nothing on its own when the value is empty', () => {
      const { onChange } = renderInput({ type: 'date', restriction: none }, '');
      expect(dateInput()).toHaveValue('');
      expect(onChange).not.toHaveBeenCalled();
    });

    it('is disabled when asked to', () => {
      const onChange = vi.fn();
      testRender(<DashboardVariableValueInput variable={{ type: 'date', restriction: none }} value={jan15} onChange={onChange} disabled />);
      expect(dateInput()).toBeDisabled();
    });

    const clearDate = async (user: ReturnType<typeof testRender>['user']) => {
      await user.click(dateInput());
      await user.keyboard('{Control>}a{/Control}{Backspace}{Enter}');
      await user.tab();
    };

    it('emits an empty value when the date is cleared', async () => {
      const { user, onChange } = renderInput({ type: 'date', restriction: none }, jan15);
      await clearDate(user);
      expect(onChange).toHaveBeenCalledWith('');
      expect(onChange).not.toHaveBeenCalledWith(expect.stringMatching(/\d{4}-/));
    });

    it('emits nothing for a cleared date when committed on blur', async () => {
      const { user, onChange } = renderInput({ type: 'date', restriction: none }, jan15, 'blur');
      await clearDate(user);
      expect(onChange).not.toHaveBeenCalled();
    });
  });
});
