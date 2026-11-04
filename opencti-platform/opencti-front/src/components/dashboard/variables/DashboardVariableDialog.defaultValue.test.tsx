import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
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
vi.mock('../../../utils/hooks/useVocabularyCategory', () => ({ default: () => ({ categoriesOptions: [] }) }));
vi.mock('../../../utils/filters/useSearchEntities', () => ({ default: () => [{}, vi.fn()] }));

// Unlike DashboardVariableDialog.test.tsx, the value input is the real one: this is about what it hands the form.
import DashboardVariableDialog from './DashboardVariableDialog';

const sector: DashboardVariable = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Sector',
  type: 'text',
  restriction: { mode: 'none' },
  defaultValue: 'Energy',
};

describe('DashboardVariableDialog default value', () => {
  beforeEach(() => {
    mocks.upsert.mockReset().mockResolvedValue(undefined);
    mocks.onClose.mockReset();
  });

  it('refuses to save a text variable whose default value was cleared, rather than saving the old one', async () => {
    const { user } = testRender(
      <DashboardVariableDialog open workspaceId="ws-1" existingVariables={[sector]} variable={sector} onClose={mocks.onClose} />,
      { userContext: createMockUserContext({}) },
    );
    const submit = screen.getByTestId('variable-dialog-submit');
    const defaultValue = screen.getByRole('textbox', { name: /Default value/ });
    expect(defaultValue).toHaveValue('Energy');
    await user.type(screen.getByRole('textbox', { name: /Name/ }), 's');
    await waitFor(() => expect(submit).toBeEnabled());

    await user.clear(defaultValue);
    expect(defaultValue).toHaveValue('');
    await waitFor(() => expect(submit).toBeDisabled());
    await user.click(submit);
    expect(mocks.upsert).not.toHaveBeenCalled();

    await user.type(defaultValue, 'Finance');
    await waitFor(() => expect(submit).toBeEnabled());
    await user.click(submit);
    await waitFor(() => expect(mocks.upsert).toHaveBeenCalledWith({ ...sector, name: 'Sectors', defaultValue: 'Finance' }));
  });
});
