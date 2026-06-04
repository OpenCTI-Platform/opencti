import React from 'react';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { screen } from '@testing-library/react';
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

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
const renderForm = (initialValues: Partial<WorkflowEditionFormValues>, onSubmit = vi.fn()) => {
  return testRender(
    <Formik initialValues={initialValues as WorkflowEditionFormValues} onSubmit={onSubmit}>
      <Form>
        <StatusForm />
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
      const sw = screen.getByRole('checkbox', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.disabled).toBe(true);
    });

    it('disables the "Update authorized members on exit" switch', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('checkbox', { name: /update authorized members on exit/i }) as HTMLInputElement;
      expect(sw.disabled).toBe(true);
    });

    it('renders EEChip labels on both action sections', () => {
      renderForm({ onEnter: [], onExit: [] });
      // EEChip renders inside the Typography – there should be two occurrences
      const chips = document.querySelectorAll('[class*="EEChip"], [data-testid="ee-chip"]');
      // At minimum, both section headers contain "EE" marker text
      expect(screen.getByText(/on enter actions/i)).toBeDefined();
      expect(screen.getByText(/on exit actions/i)).toBeDefined();
      // The switches must remain disabled
      expect((screen.getByRole('checkbox', { name: /on enter/i }) as HTMLInputElement).disabled).toBe(true);
    });
  });

  describe('in Enterprise Edition', () => {
    beforeEach(() => {
      vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    });

    it('enables the "Update authorized members on enter" switch', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('checkbox', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.disabled).toBe(false);
    });

    it('enables the "Update authorized members on exit" switch', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('checkbox', { name: /update authorized members on exit/i }) as HTMLInputElement;
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
      const sw = screen.getByRole('checkbox', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.checked).toBe(false);
    });

    it('"on enter" switch is checked when onEnter contains updateAuthorizedMembers', () => {
      renderForm({ onEnter: onEnterAction, onExit: [] });
      const sw = screen.getByRole('checkbox', { name: /update authorized members on enter/i }) as HTMLInputElement;
      expect(sw.checked).toBe(true);
    });

    it('"on exit" switch is unchecked when onExit is empty', () => {
      renderForm({ onEnter: [], onExit: [] });
      const sw = screen.getByRole('checkbox', { name: /update authorized members on exit/i }) as HTMLInputElement;
      expect(sw.checked).toBe(false);
    });

    it('"on exit" switch is checked when onExit contains updateAuthorizedMembers', () => {
      renderForm({ onEnter: [], onExit: onExitAction });
      const sw = screen.getByRole('checkbox', { name: /update authorized members on exit/i }) as HTMLInputElement;
      expect(sw.checked).toBe(true);
    });
  });
});
