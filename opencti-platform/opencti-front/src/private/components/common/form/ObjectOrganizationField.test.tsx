import React from 'react';
import { describe, it, expect, beforeAll } from 'vitest';
import { screen } from '@testing-library/react';
import { Formik, Form } from 'formik';
import testRender from '../../../../utils/tests/test-render';
import ObjectOrganizationField from './ObjectOrganizationField';

const renderField = () => testRender(
  <Formik initialValues={{ objectOrganization: [] }} onSubmit={() => {}}>
    <Form>
      <ObjectOrganizationField name="objectOrganization" label="Organization" multiple={false} />
    </Form>
  </Formik>,
);

describe('ObjectOrganizationField', () => {
  beforeAll(() => {
    // Radix primitives observe their trigger; jsdom ships no ResizeObserver and
    // the tree comes back empty without it.
    if (!('ResizeObserver' in window)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (window as any).ResizeObserver = class {
        observe() {}

        unobserve() {}

        disconnect() {}
      };
    }
  });

  it('renders the field beside the restriction alert, never inside it', () => {
    const { container } = renderField();

    const alert = container.querySelector('.MuiAlert-root');
    const field = container.querySelector('[data-combobox-field]');
    expect(alert).not.toBeNull();
    expect(field).not.toBeNull();
    expect(screen.getByText('Organizations restriction')).toBeInTheDocument();

    // The alert holds its own message only; the field is a sibling after it.
    expect(alert!.contains(field)).toBe(false);
    expect(alert!.compareDocumentPosition(field!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    // Nothing clips the field: its ancestors up to the form keep overflow visible,
    // which is what used to cut the focus ring the library paints outside the box.
    let node: HTMLElement | null = field!.parentElement;
    while (node && node !== container) {
      expect(getComputedStyle(node).overflow).not.toBe('hidden');
      node = node.parentElement;
    }
  });
});
