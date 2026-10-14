import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
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
  default: ({ variable, value, onChange, label }: {
    variable: unknown;
    value: string;
    onChange: (value: string) => void;
    label: string;
  }) => (
    <input
      aria-label={label}
      data-testid="value-input"
      data-variable={JSON.stringify(variable)}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
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

  it('shows the steps one after the other, each one once the previous is valid', async () => {
    const { user } = renderDialog();
    expect(screen.getByTestId('dashboard-variable-dialog')).toBeInTheDocument();
    // Only the name at first.
    expect(screen.queryByRole('combobox', { name: /Type/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument();
    expect(submit()).toBeDisabled();

    await user.type(nameInput(), 'Malware family');
    const type = await screen.findByRole('combobox', { name: /Type/ });
    // The type opens the step of its parameter.
    expect(screen.queryByRole('combobox', { name: /Vocabulary category/ })).not.toBeInTheDocument();
    await user.click(type);
    expect(screen.getAllByRole('option')).toHaveLength(13);
    await user.click(screen.getByRole('option', { name: 'Vocabulary' }));
    const category = await screen.findByRole('combobox', { name: /Vocabulary category/ });
    // The restriction and the default value wait for the category.
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument();
    expect(screen.queryByTestId('value-input')).not.toBeInTheDocument();
    await user.click(category);
    await user.click(screen.getByRole('option', { name: 'event_type' }));
    expect(await screen.findByRole('radiogroup')).toBeInTheDocument();
    expect(await screen.findByTestId('value-input')).toBeInTheDocument();
  });

  it('offers no restriction step for a type that cannot be restricted', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Threshold');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Numeric' }));
    expect(await screen.findByTestId('value-input')).toBeInTheDocument();
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument();
  });

  it('offers nothing but No restriction, checked, in the restriction step', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Label');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Label' }));
    const group = await screen.findByRole('radiogroup');
    const radios = within(group).getAllByRole('radio');
    expect(radios).toHaveLength(1);
    expect(radios[0]).toBeChecked();
    expect(within(group).getByText('No restriction')).toBeInTheDocument();
    expect(screen.queryByText('Manual selection')).not.toBeInTheDocument();
    expect(screen.queryByText('By filter')).not.toBeInTheDocument();
  });

  it('keeps Create disabled for an entity variable without entity type', async () => {
    const { user } = renderDialog();
    await user.type(nameInput(), 'Entity');
    await user.click(await screen.findByRole('combobox', { name: /Type/ }));
    await user.click(screen.getByRole('option', { name: 'Entity' }));
    expect(await screen.findByRole('combobox', { name: /Entity types/ })).toBeInTheDocument();
    expect(submit()).toBeDisabled();
    // The restriction waits for the entity types.
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument();
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

  it('refuses a duplicated name and does not upsert', async () => {
    const { user } = renderDialog({ existingVariables: [sector] });
    await user.type(nameInput(), 'sector');
    expect(await screen.findByText('A variable with this name already exists')).toBeInTheDocument();
    expect(submit()).toBeDisabled();
    await user.click(submit());
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(screen.queryByRole('combobox', { name: /Type/ })).not.toBeInTheDocument();
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
        killChain: screen.queryByRole('textbox', { name: /Kill chain/ }),
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
      const radios = within(await screen.findByRole('radiogroup')).getAllByRole('radio');
      const manual = screen.getByRole('radio', { name: 'Manual selection' });
      expect(radios).toContain(manual);
      expect(manual).toBeChecked();
      expect(manual).toBeDisabled();
      await user.type(nameInput(), 's');
      await user.click(submit());
      await waitFor(() => expect(mocks.onClose).toHaveBeenCalledTimes(1));
      expect(mocks.upsert).toHaveBeenCalledWith({ ...restricted, name: 'Countrys' });
    });

    it('shows the filters restriction as a disabled By filter option', async () => {
      const filters = { mode: 'and', filters: [], filterGroups: [] };
      const restricted: DashboardVariable = {
        id: '33333333-3333-4333-8333-333333333333',
        name: 'Actor',
        type: 'entity',
        entityTypes: ['Malware'],
        restriction: { mode: 'filters', filters },
        defaultValue: 'abc',
      };
      renderDialog({ variable: restricted, existingVariables: [restricted] });
      const byFilter = await screen.findByRole('radio', { name: 'By filter' });
      expect(byFilter).toBeChecked();
      expect(byFilter).toBeDisabled();
    });
  });
});
