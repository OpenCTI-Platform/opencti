import React from 'react';
import { describe, it, expect } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Formik, Form } from 'formik';
import testRender from '../utils/tests/test-render';
import PasswordTextField from './PasswordTextField';

const renderField = () => testRender(
  <Formik initialValues={{ secret: 'hunter2' }} onSubmit={() => {}}>
    <Form>
      <PasswordTextField name="secret" label="Token" />
    </Form>
  </Formik>,
);

describe('PasswordTextField', () => {
  it('renders its toggle inside the field rather than positioned over it', async () => {
    const { container } = renderField();

    const input = container.querySelector('input');
    expect(input).toHaveAttribute('type', 'password');

    const toggle = screen.getByRole('button', { name: 'Show' });
    // Inside the field shell, and laid out by it — an absolutely positioned
    // button is what used to hang off the field's vertical centre.
    expect(toggle.closest('[class*="rounded-sm"]')).not.toBeNull();
    expect(getComputedStyle(toggle).position).not.toBe('absolute');

    await userEvent.click(toggle);
    expect(container.querySelector('input')).toHaveAttribute('type', 'text');
    expect(screen.getByRole('button', { name: 'Hide' })).toBeInTheDocument();
  });
});
