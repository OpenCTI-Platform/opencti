/**
 * Contract tests for the SwitchField pivot. It carries 107 <Field> sites, and
 * before this file nothing covered it — the three regressions these tests pin
 * were all found by review, not by the suite.
 */
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Formik, Form, Field, useFormikContext } from 'formik';
import * as React from 'react';
import { describe, expect, it, vi } from 'vitest';

import SwitchField from './SwitchField';
import testRender from '../../utils/tests/test-render';

const Submitting = ({ on }: { on: boolean }) => {
  const { setSubmitting } = useFormikContext();
  // In an effect, never during render — setting it inline re-renders forever.
  React.useEffect(() => {
    if (on) setSubmitting(true);
  }, [on, setSubmitting]);
  return null;
};

const renderField = (props: Record<string, unknown> = {}, initial = false, isSubmitting = false) => testRender(
  <Formik initialValues={{ flag: initial }} onSubmit={() => {}}>
    <Form>
      <Submitting on={isSubmitting} />
      <Field component={SwitchField} type="checkbox" name="flag" label="Flag" {...props} />
    </Form>
  </Formik>,
);

describe('SwitchField pivot', () => {
  it('renders a switch, not a checkbox', () => {
    renderField();
    expect(screen.getByRole('switch', { name: /flag/i })).toBeInTheDocument();
  });

  it('reflects the Formik value when no checked prop is given', () => {
    renderField({}, true);
    expect(screen.getByRole('switch', { name: /flag/i })).toBeChecked();
  });

  it('lets a caller-supplied checked win over the Formik value', () => {
    // TriggerEditionOverview keeps its value outside Formik entirely, so the
    // override is the only thing that renders it ON.
    renderField({ checked: true }, false);
    expect(screen.getByRole('switch', { name: /flag/i })).toBeChecked();
  });

  it('honours checked={false} against a truthy Formik value', () => {
    renderField({ checked: false }, true);
    expect(screen.getByRole('switch', { name: /flag/i })).not.toBeChecked();
  });

  it('disables while the form is submitting', () => {
    renderField({}, false, true);
    expect(screen.getByRole('switch', { name: /flag/i })).toBeDisabled();
  });

  it('an explicit disabled still wins', () => {
    renderField({ disabled: true });
    expect(screen.getByRole('switch', { name: /flag/i })).toBeDisabled();
  });

  it('writes a boolean into Formik and reports the string form to onChange', async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    renderField({ onChange });
    await user.click(screen.getByRole('switch', { name: /flag/i }));
    expect(onChange).toHaveBeenCalledWith('flag', 'true');
    expect(screen.getByRole('switch', { name: /flag/i })).toBeChecked();
  });

  it('forwards onFocus — three collaborative-editing sites depend on it', async () => {
    const onFocus = vi.fn();
    const user = userEvent.setup();
    renderField({ onFocus });
    await user.tab();
    expect(onFocus).toHaveBeenCalled();
  });
});
