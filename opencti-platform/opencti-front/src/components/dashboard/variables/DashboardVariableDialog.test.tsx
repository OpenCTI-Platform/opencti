import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';

const mocks = vi.hoisted(() => ({
  upsert: vi.fn(),
  onClose: vi.fn(),
}));

vi.mock('./useDashboardVariableMutations', () => ({
  useDashboardVariableMutations: () => ({ upsert: mocks.upsert, isSubmitting: false }),
}));
// This module otherwise preloads its query on the application environment at import time.
vi.mock('../../../utils/hooks/useVocabularyCategory', () => ({
  default: () => ({ categoriesOptions: [{ value: 'event_type', label: 'event_type' }, { value: 'report_types', label: 'report_types' }] }),
}));
vi.mock('../../../utils/filters/useSearchEntities', () => ({ default: () => [{}, vi.fn()] }));
// The value inputs have their own tests: this one exposes what the dialog hands them.
vi.mock('./DashboardVariableValueInput', () => ({
  default: ({ variable, value, onChange, label, disabled }: {
    variable: unknown;
    value: string;
    onChange: (value: string) => void;
    label: string;
    disabled?: boolean;
  }) => (
    <input
      aria-label={label}
      disabled={disabled}
      data-testid="value-input"
      data-variable={JSON.stringify(variable)}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  ),
}));

vi.mock('./ValueInputs/SelectionValuesInput', () => ({
  default: ({ values, onChange, label, error }: { values: string[]; onChange: (values: string[]) => void; label: string; error?: string }) => (
    <>
      <input
        aria-label={label}
        data-testid="selection-input"
        value={values.join(',')}
        onChange={(event) => onChange(event.target.value ? event.target.value.split(',') : [])}
      />
      {error && <span>{error}</span>}
    </>
  ),
}));
// Hoisted: the mock of the rule editor below emits them.
const { rule, otherRule } = vi.hoisted(() => {
  const labelRule = (labelId: string) => ({ mode: 'and', filters: [{ key: 'objectLabel', values: [labelId], operator: 'eq', mode: 'or' }], filterGroups: [] });
  return { rule: labelRule('label-1'), otherRule: labelRule('label-2') };
});
vi.mock('./RestrictionFiltersField', () => ({
  default: ({ onChange, entityTypes }: { onChange: (filters: unknown) => void; entityTypes: string[] }) => (
    <div data-testid="rule-editor" data-entity-types={entityTypes.join()}>
      <button type="button" onClick={() => onChange(rule)}>Set rule</button>
      <button type="button" onClick={() => onChange(otherRule)}>Set other rule</button>
    </div>
  ),
}));

import DashboardVariableDialog from './DashboardVariableDialog';

const userContext = createMockUserContext({
  schema: {
    scrs: [],
    sdos: [{ id: 'Malware', label: 'Malware' }, { id: 'Report', label: 'Report' }],
    scos: [],
    smos: [],
  },
});

const sector: DashboardVariable = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Sector',
  type: 'text',
  restriction: { mode: 'none' },
  defaultValue: 'Energy',
};

const renderDialog = (props: { variable?: DashboardVariable; existingVariables?: DashboardVariable[] } = {}) => testRender(
  <DashboardVariableDialog
    open
    workspaceId="ws-1"
    existingVariables={props.existingVariables ?? []}
    variable={props.variable}
    onClose={mocks.onClose}
  />,
  { userContext },
);

const nameInput = () => screen.getByRole('textbox', { name: /Name/ });
// Anchored: the Type field may be named after its value, `Kill chain phase`.
const KILL_CHAIN_FIELD = /^Kill chain\s*\*?$/;
const submit = () => screen.getByTestId('variable-dialog-submit');

describe('DashboardVariableDialog', () => {
  beforeEach(() => {
    mocks.upsert.mockReset().mockResolvedValue(undefined);
    mocks.onClose.mockReset();
  });

  it('is a modal dialog named by its title, with the focus on the name', async () => {
    renderDialog();
    expect(screen.getByRole('dialog', { name: 'Create variable' })).toBe(screen.getByTestId('dashboard-variable-dialog'));
    await waitFor(() => expect(nameInput()).toHaveFocus());
  });

  it('is named Edit variable in edition', () => {
    renderDialog({ variable: sector, existingVariables: [sector] });
    expect(screen.getByRole('dialog', { name: 'Edit variable' })).toBeInTheDocument();
  });

  it('closes on Escape and on Cancel', async () => {
    const { user } = renderDialog();
    await user.keyboard('{Escape}');
    expect(mocks.onClose).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(mocks.onClose).toHaveBeenCalledTimes(2);
  });

  it('shows every field from the start, the ones depending on the type disabled until it is chosen', async () => {
    const { user } = renderDialog();
    expect(nameInput()).toBeEnabled();
    expect(screen.getByRole('combobox', { name: /Type/ })).toBeEnabled();
    // Generic fields standing for what the type will bring.
    expect(screen.getByRole('textbox', { name: 'Type parameter' })).toBeDisabled();
    const group = screen.getByRole('radiogroup', { name: 'Restriction' });
    expect(within(group).getByRole('radio', { name: 'No restriction' })).toBeDisabled();
    expect(screen.getByRole('textbox', { name: 'Default value' })).toBeDisabled();
    expect(submit()).toBeDisabled();

    await user.type(nameInput(), 'Malware family');
    expect(screen.getByRole('textbox', { name: 'Type parameter' })).toBeDisabled();
    await user.click(screen.getByRole('combobox', { name: /Type/ }));
    expect(screen.getAllByRole('option')).toHaveLength(13);
    await user.click(screen.getByRole('option', { name: 'Vocabulary' }));
    // The real parameter field replaces the generic one; the restriction and the value wait for the category.
    const category = await screen.findByRole('combobox', { name: /Vocabulary category/ });
    expect(category).toBeEnabled();
    expect(screen.queryByRole('textbox', { name: 'Type parameter' })).not.toBeInTheDocument();
    expect(within(screen.getByRole('radiogroup')).getByRole('radio', { name: 'No restriction' })).toBeDisabled();
    expect(screen.getByTestId('value-input')).toBeDisabled();
    await user.click(category);
    await user.click(screen.getByRole('option', { name: 'event_type' }));
    await waitFor(() => expect(screen.getByTestId('value-input')).toBeEnabled());
    expect(within(screen.getByRole('radiogroup')).getByRole('radio', { name: 'No restriction' })).toBeEnabled();
  });

  it('does not show an error on a field the user has not touched', () => {
    renderDialog();
    expect(screen.queryByText('Name is required')).not.toBeInTheDocument();
    expect(screen.queryByText('Type is required')).not.toBeInTheDocument();
    expect(screen.queryByText('Default value is required')).not.toBeInTheDocument();
  });

  it('hides the type parameter once a type without parameter is chosen, and the restriction of a type that cannot be restricted', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Threshold');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Numeric' }));
    expect(await screen.findByTestId('value-input')).toBeEnabled();
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: 'Type parameter' })).not.toBeInTheDocument();
  });

  describe('restriction', () => {
    const chooseType = async (user: ReturnType<typeof renderDialog>['user'], typeLabel: string) => {
      await user.type(nameInput(), 'Var');
      await user.click(await screen.findByRole('combobox', { name: /Type/ }));
      await user.click(screen.getByRole('option', { name: typeLabel }));
    };
    const chooseEntityType = async (user: ReturnType<typeof renderDialog>['user']) => {
      await user.click(await screen.findByRole('combobox', { name: /Entity types/ }));
      await user.click(screen.getByRole('option', { name: 'Malware' }));
      await user.keyboard('{Escape}');
    };
    const radio = (name: string) => within(screen.getByRole('radiogroup')).getByRole('radio', { name });

    it('offers the three modes for an entity variable, No restriction checked by default', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Entity');
      await chooseEntityType(user);
      expect(within(screen.getByRole('radiogroup')).getAllByRole('radio')).toHaveLength(3);
      expect(radio('No restriction')).toBeChecked();
      expect(radio('Manual selection')).toBeEnabled();
      expect(radio('By filter')).toBeEnabled();
    });

    it('does not offer By filter for a label variable', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Label');
      expect(within(screen.getByRole('radiogroup')).getAllByRole('radio')).toHaveLength(2);
      expect(screen.queryByRole('radio', { name: 'By filter' })).not.toBeInTheDocument();
    });

    it('creates a variable restricted to a selection, its default value among the selected values', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Label');
      await user.click(radio('Manual selection'));
      await user.type(screen.getByTestId('selection-input'), 'label-1,label-2');
      const valueInput = screen.getByTestId('value-input');
      expect(JSON.parse(valueInput.dataset.variable ?? '').restriction).toEqual({ mode: 'selection', values: ['label-1', 'label-2'] });
      await user.type(valueInput, 'label-2');
      await waitFor(() => expect(submit()).toBeEnabled());
      await user.click(submit());
      await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({
        type: 'label',
        restriction: { mode: 'selection', values: ['label-1', 'label-2'] },
        defaultValue: 'label-2',
      }));
    });

    it('keeps Create disabled while the selection is empty, or the default value is outside of it', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Label');
      await user.click(radio('Manual selection'));
      await user.type(screen.getByTestId('value-input'), 'label-3');
      expect(submit()).toBeDisabled();
      await user.type(screen.getByTestId('selection-input'), 'label-1');
      expect(submit()).toBeDisabled();
      expect(mocks.upsert).not.toHaveBeenCalled();
    });

    it('forgets the default value removed from the selection', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Label');
      await user.click(radio('Manual selection'));
      await user.type(screen.getByTestId('selection-input'), 'label-1,label-2');
      await user.type(screen.getByTestId('value-input'), 'label-2');
      await user.clear(screen.getByTestId('selection-input'));
      await user.type(screen.getByTestId('selection-input'), 'label-1');
      expect(screen.getByTestId('value-input')).toHaveValue('');
    });

    it('creates a variable restricted by filters, searching its default value within the rule', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Entity');
      await chooseEntityType(user);
      await user.click(radio('By filter'));
      expect(screen.getByTestId('rule-editor')).toHaveAttribute('data-entity-types', 'Malware');
      expect(submit()).toBeDisabled();
      await user.click(screen.getByRole('button', { name: 'Set rule' }));
      const valueInput = screen.getByTestId('value-input');
      expect(JSON.parse(valueInput.dataset.variable ?? '').restriction).toEqual({ mode: 'filters', filters: rule });
      await user.type(valueInput, 'malware-1');
      await waitFor(() => expect(submit()).toBeEnabled());
      await user.click(submit());
      await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({
        type: 'entity',
        restriction: { mode: 'filters', filters: rule },
        defaultValue: 'malware-1',
      }));
    });

    it('forgets the default value when the rule changes', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Entity');
      await chooseEntityType(user);
      await user.click(radio('By filter'));
      await user.click(screen.getByRole('button', { name: 'Set rule' }));
      await user.type(screen.getByTestId('value-input'), 'malware-1');
      await user.click(screen.getByRole('button', { name: 'Set other rule' }));
      expect(screen.getByTestId('value-input')).toHaveValue('');
    });

    it('forgets the default value when the mode changes, and finds the selection back', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Label');
      await user.click(radio('Manual selection'));
      await user.type(screen.getByTestId('selection-input'), 'label-1');
      await user.type(screen.getByTestId('value-input'), 'label-1');
      await user.click(radio('No restriction'));
      expect(screen.getByTestId('value-input')).toHaveValue('');
      expect(screen.queryByTestId('selection-input')).not.toBeInTheDocument();
      await user.click(radio('Manual selection'));
      expect(screen.getByTestId('selection-input')).toHaveValue('label-1');
      expect(screen.getByTestId('value-input')).toHaveValue('');
    });

    it('goes back to No restriction when the type changes to a type without restriction', async () => {
      const { user } = renderDialog();
      await chooseType(user, 'Label');
      await user.click(radio('Manual selection'));
      await user.click(screen.getByRole('combobox', { name: /Type/ }));
      await user.click(screen.getByRole('option', { name: 'Text' }));
      expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument();
      await user.type(screen.getByTestId('value-input'), 'Energy');
      await waitFor(() => expect(submit()).toBeEnabled());
      await user.click(submit());
      await waitFor(() => expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({ type: 'text', restriction: { mode: 'none' } })));
    });
  });

  it.each(['Boolean', 'Date'])('starts a %s variable without default value, and keeps Create disabled until one is chosen', async (typeLabel) => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Flag');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: typeLabel }));
    const valueInput = await screen.findByTestId('value-input');
    expect(valueInput).toBeEnabled();
    expect(valueInput).toHaveValue('');
    expect(submit()).toBeDisabled();
    await user.click(submit());
    expect(mocks.upsert).not.toHaveBeenCalled();

    await user.type(valueInput, typeLabel === 'Boolean' ? 'true' : '2026-10-13T00:00:00.000Z');
    await waitFor(() => expect(submit()).toBeEnabled());
    await user.click(submit());
    await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
    expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({ type: typeLabel.toLowerCase() }));
  });

  it('keeps Create disabled for an entity variable without entity type, with the restriction and the value disabled', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Entity');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Entity' }));
    expect(await screen.findByRole('combobox', { name: /Entity types/ })).toBeEnabled();
    expect(submit()).toBeDisabled();
    expect(within(screen.getByRole('radiogroup')).getByRole('radio', { name: 'No restriction' })).toBeDisabled();
    expect(screen.getByTestId('value-input')).toBeDisabled();
  });

  it('upserts the expected variable, with a generated id, then closes', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), '  Sector ');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Text' }));
    await user.type(await screen.findByTestId('value-input'), 'Energy');
    await waitFor(() => expect(submit()).toBeEnabled());
    await user.click(submit());
    await waitFor(() => expect(mocks.onClose).toHaveBeenCalledTimes(1));
    expect(mocks.upsert).toHaveBeenCalledTimes(1);
    expect(mocks.upsert).toHaveBeenCalledWith({
      id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/),
      name: 'Sector',
      type: 'text',
      restriction: { mode: 'none' },
      defaultValue: 'Energy',
    });
  });

  it('upserts a vocabulary variable with its category and hands a variable shape to the value input', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Event');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Vocabulary' }));
    await user.click(await screen.findByRole('combobox', { name: /Vocabulary category/ }));
    await user.click(screen.getByRole('option', { name: 'report_types' }));
    const valueInput = await screen.findByTestId('value-input');
    expect(JSON.parse(valueInput.dataset.variable ?? '')).toEqual({
      id: 'draft',
      name: 'Event',
      type: 'vocabulary',
      vocabularyCategory: 'report_types',
      restriction: { mode: 'none' },
      defaultValue: null,
    });
    await user.type(valueInput, 'threat-report');
    await user.click(submit());
    await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
    expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({
      name: 'Event',
      type: 'vocabulary',
      vocabularyCategory: 'report_types',
      defaultValue: 'threat-report',
    }));
  });

  it('upserts an entity variable with its entity types', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Entity');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Entity' }));
    await user.click(await screen.findByRole('combobox', { name: /Entity types/ }));
    await user.click(screen.getByRole('option', { name: 'Malware' }));
    await user.type(await screen.findByTestId('value-input'), 'abc');
    await waitFor(() => expect(submit()).toBeEnabled());
    await user.click(submit());
    await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
    expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({
      name: 'Entity',
      type: 'entity',
      entityTypes: ['Malware'],
      restriction: { mode: 'none' },
      defaultValue: 'abc',
    }));
  });

  it('forgets the default value when the type changes', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Threshold');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Text' }));
    await user.type(await screen.findByTestId('value-input'), 'abc');
    await user.click(screen.getByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Numeric' }));
    expect(await screen.findByTestId('value-input')).toHaveValue('');
    expect(submit()).toBeDisabled();
  });

  it('keeps the dialog open when the server rejects the variable', async () => {
    mocks.upsert.mockRejectedValue(new Error('boom'));
    const { user } = renderDialog({ variable: sector });
    await user.type(nameInput(), ' 2');
    await user.click(submit());
    await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
    expect(mocks.onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId('dashboard-variable-dialog')).toBeInTheDocument();
    await waitFor(() => expect(submit()).toBeEnabled());
  });

  it('forgets the default value when the vocabulary category changes', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Event');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Vocabulary' }));
    await user.click(await screen.findByRole('combobox', { name: /Vocabulary category/ }));
    await user.click(screen.getByRole('option', { name: 'report_types' }));
    await user.type(await screen.findByTestId('value-input'), 'threat-report');
    await waitFor(() => expect(submit()).toBeEnabled());
    await user.click(screen.getByRole('combobox', { name: /Vocabulary category/ }));
    await user.click(screen.getByRole('option', { name: 'event_type' }));
    await waitFor(() => expect(screen.getByTestId('value-input')).toHaveValue(''));
    expect(submit()).toBeDisabled();
    await user.type(screen.getByTestId('value-input'), 'conference');
    await user.click(submit());
    await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
    expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({
      vocabularyCategory: 'event_type',
      defaultValue: 'conference',
    }));
  });

  it('forgets the default value when the entity types change', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Entity');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Entity' }));
    await user.click(await screen.findByRole('combobox', { name: /Entity types/ }));
    await user.click(screen.getByRole('option', { name: 'Malware' }));
    await user.type(await screen.findByTestId('value-input'), 'abc');
    await waitFor(() => expect(submit()).toBeEnabled());
    await user.click(screen.getByRole('combobox', { name: /Entity types/ }));
    await user.click(screen.getByRole('option', { name: 'Report' }));
    await waitFor(() => expect(screen.getByTestId('value-input')).toHaveValue(''));
    expect(submit()).toBeDisabled();
  });

  describe('kill chain', () => {
    const killChainNames = (names: string[]) => ({
      data: { runtimeAttributes: { edges: names.map((name) => ({ node: { id: name, value: name } })) } },
    });

    const chooseKillChainPhaseType = async (user: ReturnType<typeof renderDialog>['user']) => {
      await user.type(nameInput(), 'Phase');
      await user.click(await screen.findByRole('combobox', { name: /Type/ }));
      await user.click(screen.getByRole('option', { name: 'Kill chain phase' }));
      return screen.findByRole('combobox', { name: KILL_CHAIN_FIELD });
    };

    it('offers the kill chains of the platform, and forgets the default value when another one is chosen', async () => {
      const { user, relayEnv } = renderDialog();
      const killChain = await chooseKillChainPhaseType(user);
      const operation = relayEnv.mock.getMostRecentOperation();
      expect(operation.request.node.operation.name).toBe('useKillChainNamesQuery');
      expect(operation.request.variables).toEqual({ first: 500 });
      act(() => {
        relayEnv.mock.resolve(operation, killChainNames(['lockheed-martin', 'mitre-attack']));
      });
      expect(screen.getByTestId('value-input')).toBeDisabled();

      await user.click(killChain);
      expect(screen.getAllByRole('option').map((option) => option.textContent)).toEqual(['lockheed-martin', 'mitre-attack']);
      await user.click(screen.getByRole('option', { name: 'mitre-attack' }));
      await waitFor(() => expect(screen.getByTestId('value-input')).toBeEnabled());
      await user.type(screen.getByTestId('value-input'), 'phase-1');
      await waitFor(() => expect(submit()).toBeEnabled());

      // Typed: the text of the current kill chain could otherwise narrow the list down to it.
      await user.clear(killChain);
      await user.type(killChain, 'lockheed');
      await user.click(screen.getByRole('option', { name: 'lockheed-martin' }));
      await waitFor(() => expect(screen.getByTestId('value-input')).toHaveValue(''));
      expect(submit()).toBeDisabled();
      await user.type(screen.getByTestId('value-input'), 'phase-2');
      await user.click(submit());
      await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({
        type: 'killChainPhase',
        killChainName: 'lockheed-martin',
        defaultValue: 'phase-2',
      }));
    });

    it('says there is no option when the platform has no kill chain', async () => {
      const { user, relayEnv } = renderDialog();
      const killChain = await chooseKillChainPhaseType(user);
      act(() => {
        relayEnv.mock.resolveMostRecentOperation(killChainNames([]));
      });
      await user.click(killChain);
      expect(screen.queryAllByRole('option')).toHaveLength(0);
      expect(screen.getByText('No available options')).toBeInTheDocument();
      expect(screen.getByTestId('value-input')).toBeDisabled();
    });

    describe('when the kill chains cannot be listed', () => {
      const HELPER = 'The kill chain names could not be loaded, type the name of the kill chain';
      const killChainText = () => screen.findByRole('textbox', { name: KILL_CHAIN_FIELD });
      const failLookup = (relayEnv: ReturnType<typeof renderDialog>['relayEnv']) => act(() => {
        relayEnv.mock.rejectMostRecentOperation(new Error('FORBIDDEN_ACCESS'));
      });

      it('replaces the select with a free text field and an explanation once the lookup has failed', async () => {
        const { user, relayEnv } = renderDialog();
        await chooseKillChainPhaseType(user);
        expect(screen.queryByText(HELPER)).not.toBeInTheDocument();
        failLookup(relayEnv);
        expect(await killChainText()).toBeEnabled();
        expect(screen.getByText(HELPER)).toBeInTheDocument();
        expect(screen.queryByRole('combobox', { name: KILL_CHAIN_FIELD })).not.toBeInTheDocument();
        expect(screen.getByTestId('value-input')).toBeDisabled();
      });

      it('creates the variable with the typed kill chain name, and forgets the default value when it changes', async () => {
        const { user, relayEnv } = renderDialog();
        await chooseKillChainPhaseType(user);
        failLookup(relayEnv);
        const killChain = await killChainText();
        await user.type(killChain, 'mitre-attack');
        await waitFor(() => expect(screen.getByTestId('value-input')).toBeEnabled());
        await user.type(screen.getByTestId('value-input'), 'phase-1');
        await waitFor(() => expect(submit()).toBeEnabled());

        await user.type(killChain, '-ics');
        await waitFor(() => expect(screen.getByTestId('value-input')).toHaveValue(''));
        expect(submit()).toBeDisabled();
        await user.type(screen.getByTestId('value-input'), 'phase-2');
        await user.click(submit());
        await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
        expect(mocks.upsert).toHaveBeenCalledWith(expect.objectContaining({
          type: 'killChainPhase',
          killChainName: 'mitre-attack-ics',
          defaultValue: 'phase-2',
        }));
      });

      it('requires a kill chain name', async () => {
        const { user, relayEnv } = renderDialog();
        await chooseKillChainPhaseType(user);
        failLookup(relayEnv);
        await killChainText();
        expect(screen.getByTestId('value-input')).toBeDisabled();
        expect(submit()).toBeDisabled();
      });

      it('locks the kill chain of an edited variable', async () => {
        const killChain: DashboardVariable = {
          id: '55555555-5555-4555-8555-555555555555',
          name: 'Phase',
          type: 'killChainPhase',
          killChainName: 'mitre-attack',
          restriction: { mode: 'none' },
          defaultValue: 'phase-1',
        };
        const { relayEnv } = renderDialog({ variable: killChain, existingVariables: [killChain] });
        failLookup(relayEnv);
        const killChainField = await killChainText();
        expect(killChainField).toBeDisabled();
        expect(killChainField).toHaveValue('mitre-attack');
      });
    });
  });

  it('refuses a duplicated name and does not upsert', async () => {
    const { user } = renderDialog({ existingVariables: [sector] });
    await user.type(nameInput(), 'sector');
    expect(await screen.findByText('A variable with this name already exists')).toBeInTheDocument();
    expect(submit()).toBeDisabled();
    await user.click(submit());
    expect(mocks.upsert).not.toHaveBeenCalled();
  });

  it('shows the quota error and refuses to create beyond 50 variables', async () => {
    const existing = Array.from({ length: 50 }, (_, index): DashboardVariable => ({
      ...sector,
      id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
      name: `Variable ${index}`,
    }));
    const { user } = renderDialog({ existingVariables: existing });
    expect(screen.getByText('A dashboard cannot hold more than 50 variables')).toBeInTheDocument();
    await user.type(nameInput(), 'One more');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Text' }));
    await user.type(await screen.findByTestId('value-input'), 'Energy');
    expect(submit()).toBeDisabled();
  });

  describe('edition', () => {
    it('locks the type and keeps the id', async () => {
      const { user } = renderDialog({ variable: sector, existingVariables: [sector] });
      expect(nameInput()).toHaveValue('Sector');
      expect(screen.getByRole('combobox', { name: /Type/ })).toBeDisabled();
      await user.type(nameInput(), 's');
      await user.click(submit());
      await waitFor(() => expect(mocks.onClose).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenCalledWith({ ...sector, name: 'Sectors' });
    });

    it('locks the type parameters and resends them untouched', async () => {
      const vocabulary: DashboardVariable = {
        id: '44444444-4444-4444-8444-444444444444',
        name: 'Event',
        type: 'vocabulary',
        vocabularyCategory: 'report_types',
        restriction: { mode: 'none' },
        defaultValue: 'threat-report',
      };
      const killChain: DashboardVariable = {
        id: '55555555-5555-4555-8555-555555555555',
        name: 'Phase',
        type: 'killChainPhase',
        killChainName: 'mitre-attack',
        restriction: { mode: 'none' },
        defaultValue: 'phase-1',
      };
      const entity: DashboardVariable = {
        id: '66666666-6666-4666-8666-666666666666',
        name: 'Actor',
        type: 'entity',
        entityTypes: ['Malware'],
        restriction: { mode: 'none' },
        defaultValue: 'abc',
      };
      const all = [vocabulary, killChain, entity];
      const parameterField = () => ({
        vocabulary: screen.queryByRole('combobox', { name: /Vocabulary category/ }),
        killChain: screen.queryByRole('combobox', { name: KILL_CHAIN_FIELD }),
        entity: screen.queryByRole('combobox', { name: /Entity types/ }),
      });

      const first = renderDialog({ variable: vocabulary, existingVariables: all });
      expect(parameterField().vocabulary).toBeDisabled();
      await first.user.type(nameInput(), 's');
      await first.user.click(submit());
      await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenLastCalledWith({ ...vocabulary, name: 'Events' });
      first.unmount();

      const second = renderDialog({ variable: killChain, existingVariables: all });
      expect(parameterField().killChain).toBeDisabled();
      await second.user.type(nameInput(), 's');
      await second.user.click(submit());
      await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(2));
      expect(mocks.upsert).toHaveBeenLastCalledWith({ ...killChain, name: 'Phases' });
      second.unmount();

      const third = renderDialog({ variable: entity, existingVariables: all });
      expect(parameterField().entity).toBeDisabled();
      await third.user.type(nameInput(), 's');
      await third.user.click(submit());
      await waitFor(() => expect(mocks.upsert).toHaveBeenCalledTimes(3));
      expect(mocks.upsert).toHaveBeenLastCalledWith({ ...entity, name: 'Actors' });
    });

    it('does not count the edited variable against its own name nor the quota', async () => {
      const { user } = renderDialog({ variable: sector, existingVariables: [sector] });
      await user.type(nameInput(), '!');
      expect(screen.queryByText('A variable with this name already exists')).not.toBeInTheDocument();
      expect(submit()).toBeEnabled();
    });

    it('resends the selection restriction untouched when the name is edited', async () => {
      const restricted: DashboardVariable = {
        id: '22222222-2222-4222-8222-222222222222',
        name: 'Country',
        type: 'label',
        restriction: { mode: 'selection', values: ['label-1', 'label-2'] },
        defaultValue: 'label-1',
      };
      const { user } = renderDialog({ variable: restricted, existingVariables: [restricted] });
      const manual = within(await screen.findByRole('radiogroup')).getByRole('radio', { name: 'Manual selection' });
      expect(manual).toBeChecked();
      expect(manual).toBeEnabled();
      expect(screen.getByTestId('selection-input')).toHaveValue('label-1,label-2');
      await user.type(nameInput(), 's');
      await user.click(submit());
      await waitFor(() => expect(mocks.onClose).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenCalledWith({ ...restricted, name: 'Countrys' });
    });

    it('resends the filters restriction untouched when the name is edited', async () => {
      const restricted: DashboardVariable = {
        id: '33333333-3333-4333-8333-333333333333',
        name: 'Actor',
        type: 'entity',
        entityTypes: ['Malware'],
        restriction: { mode: 'filters', filters: rule },
        defaultValue: 'abc',
      };
      const { user } = renderDialog({ variable: restricted, existingVariables: [restricted] });
      const byFilter = await screen.findByRole('radio', { name: 'By filter' });
      expect(byFilter).toBeChecked();
      expect(byFilter).toBeEnabled();
      await user.type(nameInput(), 's');
      await user.click(submit());
      await waitFor(() => expect(mocks.onClose).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenCalledWith({ ...restricted, name: 'Actors' });
    });
  });
});
