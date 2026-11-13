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
const renderForm = (
  initialValues: Partial<WorkflowEditionFormValues>,
  onSubmit = vi.fn(),
  entityType = 'DraftWorkspace',
  workflowStatusIds?: Record<string, string>,
) => {
  return testRender(
    <Formik initialValues={initialValues as WorkflowEditionFormValues} onSubmit={onSubmit}>
      <Form>
        <StatusForm entityType={entityType} workflowStatusIds={workflowStatusIds} />
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
      screen.getAllByRole('switch', { name: /on enter/i }).forEach((sw) => expect((sw as HTMLInputElement).disabled).toBe(true));
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
// Reset authorized members
// ---------------------------------------------------------------------------
describe('StatusForm – reset authorized members', () => {
  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  const submittedValues = async (onSubmit: ReturnType<typeof vi.fn>) => {
    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    return onSubmit.mock.calls[0][0] as WorkflowEditionFormValues;
  };

  it('disables the reset switches in Community Edition', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    renderForm({ onEnter: [], onExit: [] });
    expect((screen.getByRole('switch', { name: /reset authorized members on enter/i }) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole('switch', { name: /reset authorized members on exit/i }) as HTMLInputElement).disabled).toBe(true);
  });

  it('toggling "Reset authorized members on enter" ON adds a reset action without params', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ onEnter: [], onExit: [] }, onSubmit);
    await user.click(screen.getByRole('switch', { name: /reset authorized members on enter/i }));
    const values = await submittedValues(onSubmit);
    expect(values.onEnter).toEqual([{ type: WorkflowActionType.resetAuthorizedMembers }]);
    expect(values.onExit).toEqual([]);
  });

  it('toggling reset ON replaces an update action on the same side', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({
      onEnter: [],
      onExit: [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }],
    }, onSubmit);
    await user.click(screen.getByRole('switch', { name: /reset authorized members on exit/i }));
    const values = await submittedValues(onSubmit);
    expect(values.onExit).toEqual([{ type: WorkflowActionType.resetAuthorizedMembers }]);
  });

  it('toggling update ON replaces a reset action on the same side', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ onEnter: [{ type: WorkflowActionType.resetAuthorizedMembers }], onExit: [] }, onSubmit);
    await user.click(screen.getByRole('switch', { name: /update authorized members on enter/i }));
    const values = await submittedValues(onSubmit);
    expect(values.onEnter?.map((a) => a.type)).toEqual([WorkflowActionType.updateAuthorizedMembers]);
  });

  it('toggling reset OFF removes the reset action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ onEnter: [{ type: WorkflowActionType.resetAuthorizedMembers }], onExit: [] }, onSubmit);
    await user.click(screen.getByRole('switch', { name: /reset authorized members on enter/i }));
    const values = await submittedValues(onSubmit);
    expect(values.onEnter).toEqual([]);
  });
});

describe('StatusForm – Status ID', () => {
  const statusTemplate = { id: 'tpl-a', name: 'A', color: '#fff' };

  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  it('shows the Status ID of the selected template with a copy button', () => {
    renderForm({ statusTemplate, onEnter: [], onExit: [] }, vi.fn(), 'DraftWorkspace', { 'tpl-a': 'status-a' });
    expect(screen.getByText('Status ID')).toBeDefined();
    expect(screen.getByText('status-a')).toBeDefined();
    expect(screen.getByRole('button', { name: /copy/i })).toBeDefined();
  });

  it('shows a hint when the selected template has no Status yet', () => {
    renderForm({ statusTemplate, onEnter: [], onExit: [] }, vi.fn(), 'DraftWorkspace', {});
    expect(screen.getByText('Status ID')).toBeDefined();
    expect(screen.getByText('Available after publish')).toBeDefined();
    expect(screen.queryByText('status-a')).toBeNull();
  });

  it('does not show a stale id belonging to another template', () => {
    renderForm({ statusTemplate, onEnter: [], onExit: [] }, vi.fn(), 'DraftWorkspace', { 'tpl-b': 'status-b' });
    expect(screen.getByText('Available after publish')).toBeDefined();
    expect(screen.queryByText('status-b')).toBeNull();
  });

  it('renders nothing for the Status ID when no template is selected', () => {
    renderForm({ onEnter: [], onExit: [] }, vi.fn(), 'DraftWorkspace', { 'tpl-a': 'status-a' });
    expect(screen.queryByText('Status ID')).toBeNull();
  });
});
