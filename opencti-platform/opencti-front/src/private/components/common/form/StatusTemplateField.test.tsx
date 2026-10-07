import React from 'react';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Formik, Form, useFormikContext } from 'formik';
import testRender from '../../../../utils/tests/test-render';
import StatusTemplateField from './StatusTemplateField';

vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('../../../../relay/environment');
  return {
    ...actual,
    fetchQuery: () => ({
      toPromise: () => Promise.resolve({
        statusTemplates: { edges: [{ node: { id: 's-1', name: 'In progress', color: '#00ff00' } }] },
      }),
    }),
  };
});

const Harness = () => {
  const { setFieldValue } = useFormikContext<Record<string, unknown>>();
  return (
    <StatusTemplateField
      name="statusTemplate"
      label="Status"
      // the exact wiring StatusForm uses
      setFieldValue={(field, { value, label, color }) => setFieldValue(field, { id: value, name: label, color })}
      helpertext=""
    />
  );
};

describe('StatusTemplateField', () => {
  beforeAll(() => {
    if (!('ResizeObserver' in window)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (window as any).ResizeObserver = class {
        observe() {} unobserve() {} disconnect() {}
      };
    }
  });

  it('keeps its label after a pick, though the form stores { id, name }', async () => {
    testRender(
      <Formik initialValues={{ statusTemplate: null }} onSubmit={() => {}}>
        <Form><Harness /></Form>
      </Formik>,
    );
    const input = screen.getByRole('combobox');
    await userEvent.click(input);
    await waitFor(() => expect(screen.getByText('In progress')).toBeInTheDocument());
    await userEvent.click(screen.getByText('In progress'));
    expect((input as HTMLInputElement).value).toBe('In progress');
  });
});
