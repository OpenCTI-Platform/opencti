/**
 * Contract tests for the number path of the TextField pivot, driven through a real `<Field
 * component={TextField}>` — the shape all 526 product sites use.
 */
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Field, Form, Formik } from 'formik';
import * as React from 'react';
import { describe, expect, it } from 'vitest';

import TextField from './TextField';
import testRender from '../utils/tests/test-render';

const renderField = (props: Record<string, unknown> = {}, initial: string | number = '') => testRender(
  <Formik initialValues={{ order: initial }} onSubmit={() => {}}>
    <Form>
      <Field component={TextField} name="order" label="Order" {...props} />
    </Form>
  </Formik>,
);

const numberInput = () => screen.getByRole('spinbutton', { name: /order/i });

describe('TextField pivot — number path', () => {
  it('a Formik site reaches the library Input, not the MUI fallback', () => {
    renderField();
    // The MUI fallback stamps MuiInputBase-input on its <input>; the library
    // Input does not. This is the assertion the whole unblocker turns on.
    expect(screen.getByRole('textbox', { name: /order/i }).className).not.toContain('MuiInputBase-input');
  });

  it('renders a spinbutton with the designed stepper', () => {
    renderField({ type: 'number' });
    expect(numberInput()).toHaveAttribute('type', 'number');
    expect(screen.getByRole('button', { name: 'Increase value' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Decrease value' })).toBeInTheDocument();
  });

  it('suppresses the browser spinners so only one stepper renders', () => {
    renderField({ type: 'number' });
    expect(numberInput().className).toContain('appearance-textfield');
  });

  it('keeps the field the same size — padding goes INSIDE, height is untouched', () => {
    renderField({ type: 'number' });
    // h-9 is the field's own 36px box, unchanged by the stepper.
    expect(numberInput().className).toContain('h-9');
    // pr-7 is the room the stepper takes within that box.
    expect(numberInput().className).toContain('pr-7');
  });

  it('leaves a text field alone — same height, no stepper', () => {
    renderField();
    expect(screen.getByRole('textbox', { name: /order/i }).className).toContain('h-9');
    expect(screen.queryByRole('button', { name: 'Increase value' })).not.toBeInTheDocument();
  });

  it('forwards step, min and max to the native input', () => {
    renderField({ type: 'number', step: 5, min: 0, max: 10 });
    expect(numberInput()).toHaveAttribute('step', '5');
    expect(numberInput()).toHaveAttribute('min', '0');
    expect(numberInput()).toHaveAttribute('max', '10');
  });

  it('steps the value on click', async () => {
    const user = userEvent.setup();
    renderField({ type: 'number', step: 1 }, 3);
    await user.click(screen.getByRole('button', { name: 'Increase value' }));
    expect(numberInput()).toHaveValue(4);
  });

  it('still falls back to MUI for a prop the Input cannot place', () => {
    // The diagnostic ignores props with no value; it must still catch real ones.
    renderField({ style: { marginTop: 20 } });
    expect(screen.getByRole('textbox', { name: /order/i }).className).toContain('MuiInputBase-input');
  });
});
