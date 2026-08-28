/**
 * Contract tests for the number path of the TextField pivot.
 *
 * The pivot passes `isTypeNumber` whenever `type === 'number'`, which is what
 * carries the designed stepper without touching a call site. These tests pin
 * the two things that decision rests on: the stepper is really there, and the
 * field's BOX does not change size — the padding the stepper needs is added
 * inside it.
 *
 * They drive the pivot with an explicit props object rather than through
 * `<Field component={TextField}>`. That is deliberate and it is not a
 * convenience: Formik's `Field` always sets `children` on the props it forwards
 * (`createElement(component, {...}, children)` — three arguments, so React
 * defines the key even when the value is `undefined`), and `children` is absent
 * from the pivot's `placeable`/`nativeAttrs` sets, so `outOfContract` reads
 * `unplaceable props: children` and every Formik site takes the MUI fallback.
 * Measured, not inferred — see fds-migration/NIGHT-LOG.md. Until that is
 * decided, these tests exercise the library branch the only way it is currently
 * reachable.
 */
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Formik } from 'formik';
import * as React from 'react';
import { describe, expect, it } from 'vitest';

import TextField from './TextField';
import testRender from '../utils/tests/test-render';

type PivotProps = Record<string, unknown>;

type PivotComponentProps = Parameters<typeof TextField>[0];

const Harness = ({ extra = {}, initial = '' }: { extra?: PivotProps; initial?: string | number }) => (
  <Formik initialValues={{ order: initial }} onSubmit={() => {}}>
    {(formik) => {
      const pivotProps = {
        field: {
          name: 'order',
          value: formik.values.order,
          onChange: formik.handleChange,
          onBlur: formik.handleBlur,
        },
        form: formik,
        label: 'Order',
        ...extra,
      } as unknown as PivotComponentProps;
      return <TextField {...pivotProps} />;
    }}
  </Formik>
);

const render = (extra: PivotProps = {}, initial: string | number = '') => testRender(<Harness extra={extra} initial={initial} />);
const numberInput = () => screen.getByRole('spinbutton', { name: /order/i });

describe('TextField pivot — number path', () => {
  it('renders a spinbutton with the designed stepper', () => {
    render({ type: 'number' });
    expect(numberInput()).toHaveAttribute('type', 'number');
    expect(screen.getByRole('button', { name: 'Increase value' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Decrease value' })).toBeInTheDocument();
  });

  it('suppresses the browser spinners so only one stepper renders', () => {
    render({ type: 'number' });
    expect(numberInput().className).toContain('appearance-textfield');
  });

  it('keeps the field the same size — padding goes INSIDE, height is untouched', () => {
    render({ type: 'number' });
    // h-9 is the field's own 36px box, unchanged by the stepper.
    expect(numberInput().className).toContain('h-9');
    // pr-7 is the room the stepper takes within that box.
    expect(numberInput().className).toContain('pr-7');
  });

  it('leaves a text field alone — same height, no stepper', () => {
    render();
    const text = screen.getByRole('textbox', { name: /order/i });
    expect(text.className).toContain('h-9');
    expect(screen.queryByRole('button', { name: 'Increase value' })).not.toBeInTheDocument();
  });

  it('forwards step, min and max to the native input', () => {
    render({ type: 'number', step: 5, min: 0, max: 10 });
    expect(numberInput()).toHaveAttribute('step', '5');
    expect(numberInput()).toHaveAttribute('min', '0');
    expect(numberInput()).toHaveAttribute('max', '10');
  });

  it('steps the value on click', async () => {
    const user = userEvent.setup();
    render({ type: 'number', step: 1 }, 3);
    await user.click(screen.getByRole('button', { name: 'Increase value' }));
    expect(numberInput()).toHaveValue(4);
  });

  it('DEFECT PIN — a Formik <Field> site never reaches this branch', () => {
    // Delete when the `children` blocker is decided. Written as an assertion so
    // the day the pivot starts honouring Formik sites, this test fails and says
    // where to look, instead of the change landing on ~620 fields unannounced.
    render({ type: 'number', children: undefined });
    expect(screen.queryByRole('button', { name: 'Increase value' })).not.toBeInTheDocument();
    expect(screen.getByRole('spinbutton', { name: /order/i }).className).toContain('MuiInputBase-input');
  });
});
