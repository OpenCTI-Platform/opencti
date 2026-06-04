import React from 'react';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { Formik, Form } from 'formik';
import TransitionForm from './TransitionForm';
import testRender from '../../../../../utils/tests/test-render';
import { WorkflowActionType, CommentMode } from './utils';
import type { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import type { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';

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

vi.mock('../../../../../utils/hooks/useEnterpriseEdition', () => ({
  default: vi.fn(),
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
  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  it('renders "Enable comment" switch unchecked when comment is "disable"', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    const enableSwitch = screen.getByRole('checkbox', { name: /enable comment/i });
    expect((enableSwitch as HTMLInputElement).checked).toBe(false);
  });

  it('renders "Enable comment" switch checked when comment is "allowed"', () => {
    renderForm({ event: 'approve', comment: CommentMode.allowed, syncActions: [] });
    const enableSwitch = screen.getByRole('checkbox', { name: /enable comment/i });
    expect((enableSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('renders "Enable comment" switch checked when comment is "required"', () => {
    renderForm({ event: 'approve', comment: CommentMode.required, syncActions: [] });
    const enableSwitch = screen.getByRole('checkbox', { name: /enable comment/i });
    expect((enableSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('"Required" switch is disabled when comment is "disable"', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    const requiredSwitch = screen.getByRole('checkbox', { name: /required/i });
    expect((requiredSwitch as HTMLInputElement).disabled).toBe(true);
  });

  it('"Required" switch is enabled when comment is "allowed"', () => {
    renderForm({ event: 'approve', comment: CommentMode.allowed, syncActions: [] });
    const requiredSwitch = screen.getByRole('checkbox', { name: /required/i });
    expect((requiredSwitch as HTMLInputElement).disabled).toBe(false);
  });

  it('"Required" switch is checked when comment is "required"', () => {
    renderForm({ event: 'approve', comment: CommentMode.required, syncActions: [] });
    const requiredSwitch = screen.getByRole('checkbox', { name: /required/i });
    expect((requiredSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('toggling "Enable comment" ON sets comment to "allowed"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /enable comment/i }));

    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: CommentMode.allowed }),
        expect.anything(),
      );
    });
  });

  it('toggling "Enable comment" OFF sets comment to "disable"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: CommentMode.allowed, syncActions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /enable comment/i }));

    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: CommentMode.disabled }),
        expect.anything(),
      );
    });
  });

  it('toggling "Required" ON sets comment to "required"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: CommentMode.allowed, syncActions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /required/i }));

    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: CommentMode.required }),
        expect.anything(),
      );
    });
  });

  it('toggling "Required" OFF sets comment back to "allowed"', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: CommentMode.required, syncActions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /required/i }));

    const form = document.querySelector('form')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ comment: CommentMode.allowed }),
        expect.anything(),
      );
    });
  });
});

describe('TransitionForm – action toggles', () => {
  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  it('"Update authorized members" switch is unchecked when action is absent', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    const uamSwitch = screen.getByRole('checkbox', { name: /update authorized members/i });
    expect((uamSwitch as HTMLInputElement).checked).toBe(false);
  });

  it('"Update authorized members" switch is checked when action is present', () => {
    renderForm({
      event: 'approve',
      comment: CommentMode.disabled,
      syncActions: [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }],
    });
    const uamSwitch = screen.getByRole('checkbox', { name: /update authorized members/i });
    expect((uamSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('toggling "Update authorized members" ON adds the action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /update authorized members/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          syncActions: expect.arrayContaining([
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
      comment: CommentMode.disabled,
      syncActions: [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }],
    }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /update authorized members/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      const actions = onSubmit.mock.calls[0][0].syncActions as { type: string }[];
      expect(actions.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers)).toBe(false);
    });
  });

  it('"Validate draft" switch is unchecked when action is absent', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    const vdSwitch = screen.getByRole('checkbox', { name: /validate draft/i });
    expect((vdSwitch as HTMLInputElement).checked).toBe(false);
  });

  it('"Validate draft" switch is checked when action is present', () => {
    renderForm({
      event: 'approve',
      comment: CommentMode.disabled,
      syncActions: [{ type: WorkflowActionType.validateDraft }],
    });
    const vdSwitch = screen.getByRole('checkbox', { name: /validate draft/i });
    expect((vdSwitch as HTMLInputElement).checked).toBe(true);
  });

  it('toggling "Validate draft" ON adds the action', async () => {
    const onSubmit = vi.fn();
    const { user } = renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /validate draft/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          syncActions: expect.arrayContaining([
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
      comment: CommentMode.disabled,
      syncActions: [{ type: WorkflowActionType.validateDraft }],
    }, onSubmit);

    await user.click(screen.getByRole('checkbox', { name: /validate draft/i }));

    document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }));

    await waitFor(() => {
      const actions = onSubmit.mock.calls[0][0].syncActions as { type: string }[];
      expect(actions.some((a) => a.type === WorkflowActionType.validateDraft)).toBe(false);
    });
  });
});

describe('TransitionForm – rendering', () => {
  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  it('renders the transition name field', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    expect(screen.getByTestId('field-event')).toBeDefined();
  });

  it('renders the info alert about comments', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    expect(screen.getByText(/users will be prompted to leave a comment/i)).toBeDefined();
  });

  it('renders WorkflowConditionFilters when conditions are defined', () => {
    const emptyFilterGroup: FilterGroup = { mode: 'and', filters: [], filterGroups: [] };
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [], conditions: { filters: emptyFilterGroup } });
    expect(screen.getByTestId('workflow-condition-filters')).toBeDefined();
  });

  it('does not render WorkflowConditionFilters when conditions are undefined', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    expect(screen.queryByTestId('workflow-condition-filters')).toBeNull();
  });

  it('renders WorkflowFieldList when syncActions are defined', () => {
    renderForm({ event: 'approve', comment: CommentMode.disabled, syncActions: [] });
    expect(screen.getByTestId('workflow-field-list')).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// EE / CE gating
// ---------------------------------------------------------------------------
describe('TransitionForm – EE / CE gating', () => {
  const emptyFilterGroup: FilterGroup = { mode: 'and', filters: [], filterGroups: [] };
  const eeActions = [{ type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } }];

  it('disables EE-only switches in CE', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    renderForm({ event: 'close', comment: CommentMode.disabled, actions: [], asyncActions: [] });

    expect((screen.getByRole('checkbox', { name: /update authorized members/i }) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole('checkbox', { name: /share with organizations/i }) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole('checkbox', { name: /unshare from organizations/i }) as HTMLInputElement).disabled).toBe(true);
  });

  it('enables EE-only switches in EE', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    renderForm({ event: 'close', comment: CommentMode.disabled, actions: [], asyncActions: [] });

    expect((screen.getByRole('checkbox', { name: /update authorized members/i }) as HTMLInputElement).disabled).toBe(false);
    expect((screen.getByRole('checkbox', { name: /share with organizations/i }) as HTMLInputElement).disabled).toBe(false);
    expect((screen.getByRole('checkbox', { name: /unshare from organizations/i }) as HTMLInputElement).disabled).toBe(false);
  });

  it('"Validate draft" switch is always enabled regardless of EE status', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    renderForm({ event: 'close', comment: CommentMode.disabled, actions: [] });

    expect((screen.getByRole('checkbox', { name: /validate draft/i }) as HTMLInputElement).disabled).toBe(false);
  });

  it('renders the conditions block with pointer-events:none in CE', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    renderForm({ event: 'close', comment: CommentMode.disabled, actions: [], conditions: { filters: emptyFilterGroup } });

    const conditionFilters = screen.getByTestId('workflow-condition-filters');
    const wrapper = conditionFilters.parentElement!;
    expect(wrapper.style.pointerEvents).toBe('none');
    expect(wrapper.style.opacity).toBe('0.5');
  });

  it('renders the conditions block normally in EE', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    renderForm({ event: 'close', comment: CommentMode.disabled, actions: [], conditions: { filters: emptyFilterGroup } });

    const conditionFilters = screen.getByTestId('workflow-condition-filters');
    const wrapper = conditionFilters.parentElement!;
    expect(wrapper.style.pointerEvents).toBe('auto');
    expect(wrapper.style.opacity).toBe('1');
  });

  it('renders the WorkflowFieldList with pointer-events:none in CE when EE actions exist', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    renderForm({ event: 'close', comment: CommentMode.disabled, actions: eeActions });

    const fieldList = screen.getByTestId('workflow-field-list');
    const wrapper = fieldList.parentElement!;
    expect(wrapper.style.pointerEvents).toBe('none');
    expect(wrapper.style.opacity).toBe('0.5');
  });

  it('renders the WorkflowFieldList normally in EE', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    renderForm({ event: 'close', comment: CommentMode.disabled, actions: eeActions });

    const fieldList = screen.getByTestId('workflow-field-list');
    const wrapper = fieldList.parentElement!;
    expect(wrapper.style.pointerEvents).toBe('auto');
    expect(wrapper.style.opacity).toBe('1');
  });
});
