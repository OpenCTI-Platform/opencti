import React from 'react';
import { screen, waitFor, within } from '@testing-library/react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { describe, expect, it } from 'vitest';
import DateTimePickerField from './DateTimePickerField';
import testRender from '../utils/tests/test-render';

const schema = Yup.object().shape({
  published: Yup.date().required('The value is required').typeError('The value must be a datetime'),
});

const renderField = () => testRender(
  <Formik initialValues={{ published: null }} validationSchema={schema} onSubmit={() => {}}>
    <Form>
      <Field component={DateTimePickerField} name="published" textFieldProps={{ label: 'Published' }} />
    </Form>
  </Formik>,
);

const sections = () => within(screen.getByRole('group', { name: 'Published' })).getAllByRole('spinbutton');

describe('Component: DateTimePickerField', () => {
  it('reports the format of a partly typed date rather than a missing value', async () => {
    const { user } = renderField();

    await user.click(sections()[0]);
    await user.keyboard('2023');
    await user.tab();

    expect(await screen.findByText('The value must be a datetime')).toBeInTheDocument();
    expect(screen.queryByText('The value is required')).not.toBeInTheDocument();
    // What was typed stays in the field.
    expect(sections()[0]).toHaveTextContent('2023');
  });

  it('accepts the date once its remaining sections are typed', async () => {
    const { user } = renderField();

    await user.click(sections()[0]);
    await user.keyboard('2023');
    await user.tab();
    await screen.findByText('The value must be a datetime');

    await user.click(sections()[1]);
    await user.keyboard('12051200a');
    await user.tab();

    await waitFor(() => expect(screen.queryByText('The value must be a datetime')).not.toBeInTheDocument());
    expect(screen.queryByText('The value is required')).not.toBeInTheDocument();
  });

  it('reports a missing value when nothing is typed', async () => {
    const { user } = renderField();

    await user.click(sections()[0]);
    await user.tab();

    expect(await screen.findByText('The value is required')).toBeInTheDocument();
  });
});
