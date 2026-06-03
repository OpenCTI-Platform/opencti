import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Formik } from 'formik';
import WorkflowFieldList from './WorkflowFieldList';
import { WorkflowDataType } from './utils';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------
vi.mock('./WorkflowFieldItem', () => ({
  default: ({ field }: { field: { name: string; value: unknown } }) => (
    <div data-testid="workflow-field-item" data-name={field.name} />
  ),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const renderInFormik = (values: Record<string, unknown>, name: keyof typeof WorkflowDataType) =>
  render(
    <Formik initialValues={values} onSubmit={vi.fn()}>
      <WorkflowFieldList name={name} />
    </Formik>,
  );

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('WorkflowFieldList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('conditions rendering (isCondition=true)', () => {
    it('renders a single WorkflowFieldItem for conditions when a conditions object is present', () => {
      renderInFormik(
        { conditions: { filters: { filters: [], filterGroups: [] } } },
        WorkflowDataType.conditions,
      );
      expect(screen.getAllByTestId('workflow-field-item')).toHaveLength(1);
    });

    it('renders nothing when conditions value is falsy', () => {
      renderInFormik({ conditions: null }, WorkflowDataType.conditions);
      expect(screen.queryByTestId('workflow-field-item')).not.toBeInTheDocument();
    });
  });

  describe('array rendering (isCondition=false)', () => {
    it('renders one WorkflowFieldItem per array entry', () => {
      renderInFormik(
        {
          onEnter: [
            { type: 'updateAuthorizedMembers', params: { authorized_members: [] } },
            { type: 'validateDraft', params: {} },
          ],
        },
        WorkflowDataType.onEnter,
      );
      expect(screen.getAllByTestId('workflow-field-item')).toHaveLength(2);
    });

    it('renders nothing when the array is empty', () => {
      renderInFormik({ onEnter: [] }, WorkflowDataType.onEnter);
      expect(screen.queryByTestId('workflow-field-item')).not.toBeInTheDocument();
    });

    it('renders nothing when the value is undefined', () => {
      renderInFormik({}, WorkflowDataType.onExit);
      expect(screen.queryByTestId('workflow-field-item')).not.toBeInTheDocument();
    });
  });
});
