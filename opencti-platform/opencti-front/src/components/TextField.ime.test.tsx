import { fireEvent, screen } from '@testing-library/react';
import { Field, Form, Formik } from 'formik';
import * as React from 'react';
import { describe, expect, it, vi } from 'vitest';

import TextField from './TextField';
import testRender from '../utils/tests/test-render';

describe('TextField keys while an input method composes text', () => {
  const renderField = () => {
    const onSubmit = vi.fn();
    const onKeyDown = vi.fn();
    const { user } = testRender(
      <Formik initialValues={{ name: '' }} onSubmit={() => {}}>
        <Form>
          <Field component={TextField} name="name" label="Name" onSubmit={onSubmit} />
          <Field component={TextField} name="other" label="Other" onKeyDown={onKeyDown} />
        </Form>
      </Formik>,
    );
    return { user, onSubmit, onKeyDown };
  };

  it('does not submit on the Enter confirming the composition (isComposing, keyCode 229)', async () => {
    const { user, onSubmit } = renderField();
    await user.type(screen.getByLabelText('Name'), 'abc');

    fireEvent.keyDown(screen.getByLabelText('Name'), { key: 'Enter', isComposing: true });
    fireEvent.keyDown(screen.getByLabelText('Name'), { key: 'Enter', keyCode: 229 });
    expect(onSubmit).not.toHaveBeenCalled();

    await user.keyboard('{Enter}');
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it('does not forward the keys of the composition to a caller onKeyDown', () => {
    const { onKeyDown } = renderField();
    fireEvent.keyDown(screen.getByLabelText('Other'), { key: 'Escape', isComposing: true });
    expect(onKeyDown).not.toHaveBeenCalled();
    fireEvent.keyDown(screen.getByLabelText('Other'), { key: 'Escape' });
    expect(onKeyDown).toHaveBeenCalledWith('Escape');
  });
});
