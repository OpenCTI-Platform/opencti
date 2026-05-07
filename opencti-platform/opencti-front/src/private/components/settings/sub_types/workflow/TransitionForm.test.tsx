import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { Formik, Form } from 'formik';
import TransitionForm from './TransitionForm';
import testRender from '../../../../../utils/tests/test-render';
import { WorkflowActionType } from './utils';
import type { WorkflowEditionFormValues } from './WorkflowEditionDrawer';

// ---------------------------------------------------------------------------
// Mock heavy sub-components with no relevance to the tested logic
// ---------------------------------------------------------------------------
vi.mock('./WorkflowFieldList', () => ({
  default: () => <div data-testid="workflow-field-list" />,
}));

vi.mock('./WorkflowConditionFilters', () => ({
  default: () => <div data-testid="workflow-condition-filters" />,
}));

vi.mock('../../../../../components/TextField', () => ({
  default: ({ field }: { field: { name: string } }) => <input data-testid={`field-${field.name}`} />,
}));

// ---------------------------------------------------------------------------
// Helper: render TransitionForm inside a Formik context
// ---------------------------------------------------------------------------
const renderForm = (initialValues: Partial<WorkflowEditionFormValues>, onSubmit = vi.fn()) => {
  return testRender(
    <Formik initialValues={initialValues as WorkflowEditionFormValues} onSubmit={onSubmit}>
      <Form>
        <TransitionForm />
      </Form>
    </Formik>,
  );
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('TransitionForm – comment section', () => {
  it('renders "Enable comment" switch unchecked when comment is "disable"', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    const enableSwitch = screen.getByRole('checkbox', { name: /enable comment/i });
    expect((enableSwitch as HTMLInputElement).checked).toBe(false);
  });

  it('renders "Enable comment" switch checked when comment is "allowed"', () => {
    renderForm({ event: 'approve', comment: 'allowed', actions: [] });
    const enableSwitch = screen.getByRole('checkbox', { name: /enable comment/i });
    expect((enableSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('renders "Enable comment" switch checked when comment is "required"', () => {
    renderForm({ event: 'approve', comment: 'required', actions: [] });
    const enableSwitch = screen.getByRole('checkbox', { name: /enable comment/i });
    expect((enableSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('"Required" switch is disabled when comment is "disable"', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    const requiredSwitch = screen.getByRole('checkbox', { name: /required/i });
    expect((requiredSwitch as HTMLInputElement).disabled).toBe(true);
  });

  it('"Required" switch is enabled when comment is "allowed"', () => {
    renderForm({ event: 'approve', comment: 'allowed', actions: [] });
    const requiredSwitch = screen.getByRole('checkbox', { name: /required/i });
    expect((requiredSwitch as HTMLInputElement).disabled).toBe(false);
  });

  it('"Required" switch is checked when comment is "required"', () => {
    renderForm({ event: 'approve', comment: 'required', actions: [] });
    const requiredSwitch = screen.getByRole('checkbox', { name: /required/i });
    expect((requiredSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('toggling "Enable comment" ON sets comment to "allowed"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: 'disable', actions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /enable comment/i }));

    await user.click(screen.getByRole('button', { name: /submit/i }).parentElement!.closest('form')!);
    // Trigger submit via form
    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: 'allowed' }),
        expect.anything(),
      );
    });
  });

  it('toggling "Enable comment" OFF sets comment to "disable"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: 'allowed', actions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /enable comment/i }));

    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: 'disable' }),
        expect.anything(),
      );
    });
  });

  it('toggling "Required" ON sets comment to "required"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: 'allowed', actions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /required/i }));

    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: 'required' }),
        expect.anything(),
      );
    });
  });

  it('toggling "Required" OFF sets comment back to "allowed"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: 'required', actions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /required/i }));

    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: 'allowed' }),
        expect.anything(),
      );
    });
  });
});

describe('TransitionForm – action toggles', () => {
  it('"Update authorized members" switch is unchecked when action is absent', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    const uamSwitch = screen.getByRole('checkbox', { name: /update authorized members/i });
    expect((uamSwitch as HTMLInputElement).checked).toBe(false);
  });

  it('"Update authorized members" switch is checked when action is present', () => {
    renderForm({
      event: 'approve',
      comment: 'disable',
      actions: [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }],
    });
    const uamSwitch = screen.getByRole('checkbox', { name: /update authorized members/i });
    expect((uamSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('toggling "Update authorized members" ON adds the action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: 'disable', actions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /update authorized members/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          actions: expect.arrayContaining([
            expect.objectContaining({ type: WorkflowActionType.updateAuthorizedMembers }),
          ]),
        }),
        expect.anything(),
      );
    });
  });

  it('toggling "Update authorized members" OFF removes the action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({
      event: 'approve',
      comment: 'disable',
      actions: [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }],
    }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /update authorized members/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      const actions = onSubmit.mock.calls[0][0].actions as { type: string }[];
      expect(actions.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers)).toBe(false);
    });
  });

  it('"Validate draft" switch is unchecked when action is absent', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    const vdSwitch = screen.getByRole('checkbox', { name: /validate draft/i });
    expect((vdSwitch as HTMLInputElement).checked).toBe(false);
  });

  it('"Validate draft" switch is checked when action is present', () => {
    renderForm({
      event: 'approve',
      comment: 'disable',
      actions: [{ type: WorkflowActionType.validateDraft }],
    });
    const vdSwitch = screen.getByRole('checkbox', { name: /validate draft/i });
    expect((vdSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('toggling "Validate draft" ON adds the action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: 'disable', actions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /validate draft/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          actions: expect.arrayContaining([
            expect.objectContaining({ type: WorkflowActionType.validateDraft }),
          ]),
        }),
        expect.anything(),
      );
    });
  });

  it('toggling "Validate draft" OFF removes the action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({
      event: 'approve',
      comment: 'disable',
      actions: [{ type: WorkflowActionType.validateDraft }],
    }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /validate draft/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      const actions = onSubmit.mock.calls[0][0].actions as { type: string }[];
      expect(actions.some((a) => a.type === WorkflowActionType.validateDraft)).toBe(false);
    });
  });
});

describe('TransitionForm – rendering', () => {
  it('renders the transition name field', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    expect(screen.getByTestId('field-event')).toBeDefined();
  });

  it('renders the info alert about comments', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    expect(screen.getByText(/users will be prompted to leave a comment/i)).toBeDefined();
  });

  it('renders WorkflowConditionFilters when conditions are defined', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [], conditions: { filters: {} as any } });
    expect(screen.getByTestId('workflow-condition-filters')).toBeDefined();
  });

  it('does not render WorkflowConditionFilters when conditions are undefined', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    expect(screen.queryByTestId('workflow-condition-filters')).toBeNull();
  });

  it('renders WorkflowFieldList when actions are defined', () => {
    renderForm({ event: 'approve', comment: 'disable', actions: [] });
    expect(screen.getByTestId('workflow-field-list')).toBeDefined();
  });
});

