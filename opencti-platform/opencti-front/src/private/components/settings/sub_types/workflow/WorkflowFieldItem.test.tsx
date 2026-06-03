import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Formik } from 'formik';
import WorkflowFieldItem from './WorkflowFieldItem';
import type { FieldProps } from 'formik';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------
vi.mock('./WorkflowConditionFilters', () => ({
  default: () => <div data-testid="condition-filters" />,
}));

vi.mock('@components/common/form/AuthorizedMembersField', () => ({
  default: () => <div data-testid="authorized-members-field" />,
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const makeFieldProps = (
  name: string,
  value: unknown,
  isCondition = false,
): FieldProps & { isCondition?: boolean } => ({
  field: { name, value, onChange: vi.fn(), onBlur: vi.fn() },
  form: {
    values: { [name]: value },
    errors: {},
    touched: {},
    isSubmitting: false,
    isValidating: false,
    submitCount: 0,
    setFieldValue: vi.fn(),
  } as unknown as FieldProps['form'],
  meta: { value, error: undefined, touched: false, initialTouched: false, initialValue: undefined, initialError: undefined },
  isCondition,
});

const renderItem = (props: ReturnType<typeof makeFieldProps>) =>
  render(
    <Formik initialValues={{}} onSubmit={vi.fn()}>
      <WorkflowFieldItem {...props} />
    </Formik>,
  );

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('WorkflowFieldItem', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('condition rendering (isCondition=true)', () => {
    it('renders WorkflowConditionFilters when isCondition is true', () => {
      renderItem(makeFieldProps('conditions', {}, true));
      expect(screen.getByTestId('condition-filters')).toBeInTheDocument();
    });

    it('does not render AuthorizedMembersField when isCondition is true', () => {
      renderItem(makeFieldProps('conditions', {}, true));
      expect(screen.queryByTestId('authorized-members-field')).not.toBeInTheDocument();
    });
  });

  describe('action rendering (isCondition=false)', () => {
    it('renders AuthorizedMembersField for updateAuthorizedMembers type', () => {
      renderItem(
        makeFieldProps('onEnter[0]', { type: 'updateAuthorizedMembers', params: { authorized_members: [] } }),
      );
      expect(screen.getByTestId('authorized-members-field')).toBeInTheDocument();
    });

    it('does not render WorkflowConditionFilters for action items', () => {
      renderItem(
        makeFieldProps('onEnter[0]', { type: 'updateAuthorizedMembers', params: { authorized_members: [] } }),
      );
      expect(screen.queryByTestId('condition-filters')).not.toBeInTheDocument();
    });

    it('renders nothing for an unrecognised action type', () => {
      const { container } = renderItem(
        makeFieldProps('onEnter[0]', { type: 'unknownAction', params: {} }),
      );
      // Component returns null → only the Formik wrapper renders
      expect(screen.queryByTestId('authorized-members-field')).not.toBeInTheDocument();
      expect(screen.queryByTestId('condition-filters')).not.toBeInTheDocument();
      expect(container).toBeEmptyDOMElement();
    });
  });
});
