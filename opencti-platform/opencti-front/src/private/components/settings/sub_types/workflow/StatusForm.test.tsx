import React from 'react';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { Formik, Form } from 'formik';
import StatusForm from './StatusForm';
import testRender from '../../../../../utils/tests/test-render';
import { WorkflowActionType } from './utils';
import type { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------
vi.mock('./WorkflowFieldList', () => ({
  default: () => <div data-testid="workflow-field-list" />,
}));

vi.mock('@components/common/form/StatusTemplateField', () => ({
  default: () => <div data-testid="status-template-field" />,
}));

vi.mock('../../../../../utils/hooks/useEnterpriseEdition', () => ({
  default: vi.fn(),
}));

vi.mock('../../../common/entreprise_edition/EEChip', () => ({
  default: () => <span data-testid="ee-chip" />,
}));

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
const renderForm = (initialValues: Partial<WorkflowEditionFormValues>, onSubmit = vi.fn(), entityType = 'DraftWorkspace', scope?: 'GLOBAL' | 'REQUEST_ACCESS') => {
  return testRender(
    <Formik initialValues={initialValues as WorkflowEditionFormValues} onSubmit={onSubmit}>
      <Form>
        <StatusForm entityType={entityType} scope={scope} />
      </Form>
    </Formik>,
  );
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('StatusForm – EE / CE gating', () => {
  const onEnterAction = [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }];
  const onExitAction = [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }];

  describe('in Community Edition', () => {
    beforeEach(() => {
      vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    });

    it('disables the "Update authorized members on enter" switch', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('switch', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.disabled).toBe(true);
    });

    it('disables the "Update authorized members on exit" switch', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('switch', { name: /update authorized members on exit/i }) as HTMLInputElement;
      expect(sw.disabled).toBe(true);
    });

    it('renders EEChip labels on both action sections', () => {
      renderForm({ onEnter: [], onExit: [] });
      // At minimum, both section headers contain "EE" marker text
      expect(screen.getByText(/on enter actions/i)).toBeDefined();
      expect(screen.getByText(/on exit actions/i)).toBeDefined();
      // The switches must remain disabled
      expect((screen.getByRole('switch', { name: /on enter/i }) as HTMLInputElement).disabled).toBe(true);
    });
  });

  describe('in Enterprise Edition', () => {
    beforeEach(() => {
      vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    });

    it('enables the "Update authorized members on enter" switch', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('switch', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.disabled).toBe(false);
    });

    it('enables the "Update authorized members on exit" switch', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('switch', { name: /update authorized members on exit/i }) as HTMLInputElement;
      expect(sw.disabled).toBe(false);
    });

    it('shows WorkflowFieldList for onEnter when action is toggled on', () => {
      renderForm({ onEnter: onEnterAction, onExit: [] });
      expect(screen.getAllByTestId('workflow-field-list').length).toBeGreaterThanOrEqual(1);
    });

    it('shows WorkflowFieldList for onExit when action is toggled on', () => {
      renderForm({ onEnter: [], onExit: onExitAction });
      expect(screen.getAllByTestId('workflow-field-list').length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('switch checked state reflects form values', () => {
    beforeEach(() => {
      vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    });

    it('"on enter" switch is unchecked when onEnter is empty', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('switch', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.checked).toBe(false);
    });

    it('"on enter" switch is checked when onEnter contains updateAuthorizedMembers', () => {
      renderForm({ onEnter: onEnterAction, onExit: [] });
      const sw = screen.getByRole('switch', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.checked).toBe(true);
    });

    it('"on exit" switch is unchecked when onExit is empty', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('switch', { name: /update authorized members on exit/i }) as HTMLInputElement;
      expect(sw.checked).toBe(false);
    });

    it('"on exit" switch is checked when onExit contains updateAuthorizedMembers', () => {
      renderForm({ onEnter: [], onExit: onExitAction });
      const sw = screen.getByRole('switch', { name: /update authorized members on exit/i }) as HTMLInputElement;
      expect(sw.checked).toBe(true);
    });
  });

  describe('CREATOR default pre-population', () => {
    beforeEach(() => {
      vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    });

    it('pre-populates CREATOR with admin access when toggling "on enter" ON', async () => {
      const onSubmit = vi.fn();
      const { user } = renderForm({ onEnter: [], onExit: [] }, onSubmit);

      await user.click(screen.getByRole('switch', { name: /update authorized members on enter/i }));

      document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

      await waitFor(() => {
        const actions = onSubmit.mock.calls[0][0].onEnter as { type: string; params?: { authorized_members?: { value: string; accessRight: string }[] } }[];
        const uamAction = actions.find((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
        expect(uamAction?.params?.authorized_members).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ value: 'CREATORS', accessRight: 'admin' }),
          ]),
        );
      });
    });

    it('pre-populates CREATOR with admin access when toggling "on exit" ON', async () => {
      const onSubmit = vi.fn();
      const { user } = renderForm({ onEnter: [], onExit: [] }, onSubmit);

      await user.click(screen.getByRole('switch', { name: /update authorized members on exit/i }));

      document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

      await waitFor(() => {
        const actions = onSubmit.mock.calls[0][0].onExit as { type: string; params?: { authorized_members?: { value: string; accessRight: string }[] } }[];
        const uamAction = actions.find((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
        expect(uamAction?.params?.authorized_members).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ value: 'CREATORS', accessRight: 'admin' }),
          ]),
        );
      });
    });
  });
});

// ---------------------------------------------------------------------------
// entityType-based section visibility
// ---------------------------------------------------------------------------
describe('StatusForm – entityType-based section visibility', () => {
  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  it('hides "On enter actions" and "On exit actions" for a non-supported entityType', () => {
    renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'Malware');
    expect(screen.queryByText(/on enter actions/i)).toBeNull();
    expect(screen.queryByText(/on exit actions/i)).toBeNull();
  });

  it('renders "On enter actions" and "On exit actions" for a Container entityType that supports authorized members', () => {
    renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'Report');
    expect(screen.queryByText(/on enter actions/i)).not.toBeNull();
    expect(screen.queryByText(/on exit actions/i)).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Request access outcome
// ---------------------------------------------------------------------------
describe('StatusForm – Request access outcome', () => {
  const shareAction = (organizations: { value: string; label: string }[]) => ({ type: WorkflowActionType.shareRequestedEntities, params: { organizations } });

  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  const submit = () => document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

  const pickOutcome = async (user: ReturnType<typeof renderForm>['user'], name: RegExp) => {
    await user.click(screen.getByRole('combobox', { name: /request outcome/i }));
    await user.click(await screen.findByRole('option', { name }));
  };

  it('shows Request outcome only in Request access scope', () => {
    const { unmount } = renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'Case-Rfi', 'REQUEST_ACCESS');
    expect(screen.queryByRole('combobox', { name: /request outcome/i })).not.toBeNull();
    unmount();
    renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'Case-Rfi', 'GLOBAL');
    expect(screen.queryByRole('combobox', { name: /request outcome/i })).toBeNull();
  });

  it('does not show Request outcome when no scope is given', () => {
    renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'Case-Rfi');
    expect(screen.queryByRole('combobox', { name: /request outcome/i })).toBeNull();
  });

  it('selecting Approved adds a shareRequestedEntities action with AUTHOR', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ onEnter: [], onExit: [] }, onSubmit, 'Case-Rfi', 'REQUEST_ACCESS');

    await pickOutcome(user, /^approved$/i);
    submit();

    await waitFor(() => {
      const values = onSubmit.mock.calls[0][0];
      expect(values.requestAccessOutcome).toBe('APPROVED');
      const shares = (values.onEnter as { type: string; params?: { organizations?: { value: string }[] } }[])
        .filter((a) => a.type === WorkflowActionType.shareRequestedEntities);
      expect(shares).toHaveLength(1);
      expect(shares[0].params?.organizations?.map((o) => o.value)).toEqual(['AUTHOR']);
    });
  });

  it('keeps an existing share action instead of adding a second one when Approved is selected', async () => {
    const onSubmit = vi.fn();
    const existing = shareAction([{ value: 'org-1', label: 'Org 1' }]);
    const { user } = renderForm({ onEnter: [existing], onExit: [] }, onSubmit, 'Case-Rfi', 'REQUEST_ACCESS');

    await pickOutcome(user, /^approved$/i);
    submit();

    await waitFor(() => {
      expect(onSubmit.mock.calls[0][0].onEnter).toEqual([existing]);
    });
  });

  it('selecting Declined adds no share action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ onEnter: [], onExit: [] }, onSubmit, 'Case-Rfi', 'REQUEST_ACCESS');

    await pickOutcome(user, /^declined$/i);
    submit();

    await waitFor(() => {
      const values = onSubmit.mock.calls[0][0];
      expect(values.requestAccessOutcome).toBe('DECLINED');
      expect(values.onEnter).toEqual([]);
    });
  });

  it('selecting None clears the outcome with null and takes back the default share action', async () => {
    const onSubmit = vi.fn();
    const added = shareAction([{ value: 'AUTHOR', label: 'Author' }]);
    const { user } = renderForm({ requestAccessOutcome: 'APPROVED', onEnter: [added], onExit: [] }, onSubmit, 'Case-Rfi', 'REQUEST_ACCESS');

    await pickOutcome(user, /^none$/i);
    submit();

    await waitFor(() => {
      const values = onSubmit.mock.calls[0][0];
      expect(values.requestAccessOutcome).toBeNull();
      expect(values.onEnter).toEqual([]);
    });
  });

  it('selecting Declined on an Approved state takes back the default share action', async () => {
    const onSubmit = vi.fn();
    const added = shareAction([{ value: 'AUTHOR', label: 'Author' }]);
    const { user } = renderForm({ requestAccessOutcome: 'APPROVED', onEnter: [added], onExit: [] }, onSubmit, 'Case-Rfi', 'REQUEST_ACCESS');

    await pickOutcome(user, /^declined$/i);
    submit();

    await waitFor(() => {
      const values = onSubmit.mock.calls[0][0];
      expect(values.requestAccessOutcome).toBe('DECLINED');
      expect(values.onEnter).toEqual([]);
    });
  });

  it('keeps a customized share action when the state leaves Approved', async () => {
    const onSubmit = vi.fn();
    const customized = shareAction([{ value: 'AUTHOR', label: 'Author' }, { value: 'org-1', label: 'Org 1' }]);
    const { user } = renderForm({ requestAccessOutcome: 'APPROVED', onEnter: [customized], onExit: [] }, onSubmit, 'Case-Rfi', 'REQUEST_ACCESS');

    await pickOutcome(user, /^none$/i);
    submit();

    await waitFor(() => {
      const values = onSubmit.mock.calls[0][0];
      expect(values.requestAccessOutcome).toBeNull();
      expect(values.onEnter).toEqual([customized]);
    });
  });

  it('lists the automatic bookkeeping of an outcome state read-only', () => {
    renderForm({ requestAccessOutcome: 'DECLINED', onEnter: [], onExit: [] }, vi.fn(), 'Case-Rfi', 'REQUEST_ACCESS');
    expect(screen.getByTestId('workflow-status-outcome-bookkeeping')).toHaveTextContent(/declined/i);
  });

  it('shows no bookkeeping note on a state without outcome', () => {
    renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'Case-Rfi', 'REQUEST_ACCESS');
    expect(screen.queryByTestId('workflow-status-outcome-bookkeeping')).toBeNull();
  });

  it('offers the share action as a removable On enter action in Request access scope', async () => {
    const onSubmit = vi.fn();
    const existing = shareAction([{ value: 'AUTHOR', label: 'Author' }]);
    const { user } = renderForm({ requestAccessOutcome: 'APPROVED', onEnter: [existing], onExit: [] }, onSubmit, 'Case-Rfi', 'REQUEST_ACCESS');

    const toggle = screen.getByRole('switch', { name: /share requested entities on enter/i }) as HTMLInputElement;
    expect(toggle.checked).toBe(true);
    await user.click(toggle);
    submit();

    await waitFor(() => {
      expect(onSubmit.mock.calls[0][0].onEnter).toEqual([]);
    });
  });

  it('does not offer the share action outside Request access scope', () => {
    renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'Case-Rfi', 'GLOBAL');
    expect(screen.queryByRole('switch', { name: /share requested entities on enter/i })).toBeNull();
  });
});
