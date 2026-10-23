/**
 * Contract tests for the slots a caller passes to the MUI path of the TextField pivot, driven
 * through a real `<Field component={TextField}>`.
 */
import { screen } from '@testing-library/react';
import { Field, Form, Formik } from 'formik';
import * as React from 'react';
import { describe, expect, it } from 'vitest';

import TextField from './TextField';
import testRender from '../utils/tests/test-render';

const renderField = (props: Record<string, unknown> = {}) => testRender(
  <Formik initialValues={{ key: '' }} onSubmit={() => {}}>
    <Form>
      <Field component={TextField} name="key" label="Key" {...props} />
    </Form>
  </Formik>,
);

describe('TextField pivot — caller slots', () => {
  it('renders the adornments of the caller input slot', () => {
    renderField({ slotProps: { input: { startAdornment: <span>prefix/</span>, endAdornment: <span>suffix</span> } } });
    expect(screen.getByText('prefix/')).toBeInTheDocument();
    expect(screen.getByText('suffix')).toBeInTheDocument();
  });

  it('resolves a caller input slot given as a function', () => {
    renderField({ slotProps: { input: () => ({ startAdornment: <span>prefix/</span> }) } });
    expect(screen.getByText('prefix/')).toBeInTheDocument();
  });

  it('puts its own start adornment in place of the caller one', () => {
    renderField({
      startAdornment: <span>wrapper/</span>,
      slotProps: { input: { startAdornment: <span>caller/</span> } },
    });
    expect(screen.getByText('wrapper/')).toBeInTheDocument();
    expect(screen.queryByText('caller/')).not.toBeInTheDocument();
  });

  it('forwards the caller html input and label slots', () => {
    renderField({ slotProps: { htmlInput: { maxLength: 3 }, inputLabel: { shrink: true } } });
    expect(screen.getByRole('textbox', { name: 'Key' })).toHaveAttribute('maxlength', '3');
    expect(screen.getByText('Key', { selector: 'label' })).toHaveAttribute('data-shrink', 'true');
  });
});
